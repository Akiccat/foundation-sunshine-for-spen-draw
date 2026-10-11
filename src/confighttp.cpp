/**
 * @file src/confighttp.cpp
 * @brief Definitions for the Web UI Config HTTP server.
 *
 * @todo Authentication, better handling of routes common to nvhttp, cleanup
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include "process.h"

#include <array>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <latch>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <cstdio>
#include <ctime>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#endif

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <boost/algorithm/string.hpp>

#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>
#include <Simple-Web-Server/utility.hpp>
#include <boost/asio/ssl/context_base.hpp>

#include "config.h"
#include "image_enhancement/api.h"
#include "image_enhancement/config.h"
#include "confighttp.h"
#include "clipboard_http.h"
#include "text_context/http.h"
#include "ai/credential_store.h"
#include "crypto.h"
#include "display_device/color_profile.h"
#include "display_device/session.h"
#include "file_mapping/file_mapping_store.h"
#include "file_handler.h"
#include "globals.h"
#include "hdr/client_display_capabilities.h"
#include "http_util.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "nvenc/frame_budget.h"
#include "perf_recorder.h"
#include "platform/common.h"
#include "platform/run_command.h"
#include "rtsp.h"
#include "src/display_device/to_string.h"
#include "src/tray/tray_http.h"
#include "stream.h"
#include "utility.h"
#include "uuid.h"
#include "video.h"
#include "version.h"
#include "webhook/webhook.h"
#include "widget_http.h"
#include "webhook/webhook_api.h"

#ifdef _WIN32
  #include "ds5/config_api.h"
  #include <iphlpapi.h>
  #include "platform/run_command.h"
  #include <tlhelp32.h>  // CreateToolhelp32Snapshot, for the "app is running" check
  #include <cctype>  // std::tolower for case-insensitive app matching
  #include "display_device/vdd_utils.h"
  #include "platform/windows/display_device/color_profile.h"
  #include "platform/windows/mic_write.h"
  #include "platform/windows/vulkan_hdr_bridge_session.h"
#endif

using namespace std::literals;
using json = nlohmann::json;

namespace confighttp {
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  // Prevent saveApp/deleteApp concurrent write to file_apps causing file corruption, non-blocking
  // return busy if not acquired
  static std::atomic<bool> apps_writing { false };
  static std::mutex file_mapping_store_transaction_mutex;

  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;

  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;

  enum class op_e {
    ADD,  ///< Add client
    REMOVE  ///< Remove client
  };

  void
  print_req(const req_https_t &request) {
    std::ostringstream log_stream;
    log_stream << "Request - TUNNEL: HTTPS"
               << ", METHOD: " << request->method
               << ", PATH: " << request->path;
    
    // Headers stay disabled because authentication and proxy headers may
    // contain credentials.
    /*
    // Headers
    if (!request->header.empty()) {
      log_stream << ", HEADERS: ";
      bool first = true;
      for (auto &[name, val] : request->header) {
        if (!first) log_stream << ", ";
        log_stream << name << "=" << (name == "Authorization" ? "CREDENTIALS REDACTED" : val);
        first = false;
      }
    }
    
    */

    static constexpr std::array safe_query_parameters {
      "bitrate"sv,
      "clientname"sv,
    };
    auto query_params = request->parse_query_string();
    http_util::append_allowed_request_log_fields(
      log_stream,
      ", PARAMS: "sv,
      query_params,
      safe_query_parameters,
      "&"sv
    );
    
    BOOST_LOG(verbose) << log_stream.str();
  }

  /**
   * @brief Send a response.
   * @param response The HTTP response object.
   * @param output_tree The JSON tree to send.
   */
  void send_response(resp_https_t response, const nlohmann::json &output_tree) {
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(output_tree.dump(), headers);
  }

  /**
   * @brief Validate the request content type and send bad request when mismatch.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param contentType The expected content type.
   * @return true if the request's Content-Type matches the expected type.
   *
   * Backport of upstream LizardByte/Sunshine 738ac93a0ec1 (CVE-2025-53095).
   * AlkaidLab does not have upstream's bad_request() helper, so the bad-request
   * response is inlined here.
   */
  bool check_content_type(resp_https_t response, req_https_t request, const std::string &contentType) {
    auto send_bad_request = [response](const std::string &error_message) {
      nlohmann::json tree;
      tree["status_code"] = 400;
      tree["status"] = false;
      tree["error"] = error_message;
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", "application/json");
      response->write(SimpleWeb::StatusCode::client_error_bad_request, tree.dump(), headers);
    };
    auto requestContentType = request->header.find("content-type");
    if (requestContentType == request->header.end()) {
      send_bad_request("Content type not provided");
      return false;
    }
    if (!http_util::content_type_matches(requestContentType->second, contentType)) {
      send_bad_request("Content type mismatch");
      return false;
    }
    return true;
  }

  namespace {
    struct request_header_value_t {
      bool valid;
      std::optional<std::string_view> value;
    };

    request_header_value_t
    get_single_request_header(const req_https_t &request, const std::string_view name) {
      const auto range = request->header.equal_range(std::string { name });
      if (range.first == range.second) {
        return { true, std::nullopt };
      }

      auto first = range.first;
      const auto value = std::string_view { first->second };
      if (++first != range.second) {
        return { false, std::nullopt };
      }
      return { true, value };
    }

    void
    send_cross_site_forbidden(resp_https_t response) {
      const nlohmann::json body {
        { "status", false },
        { "error", "Cross-site request denied" },
      };
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", "application/json");
      headers.emplace("X-Frame-Options", "DENY");
      headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
      response->write(SimpleWeb::StatusCode::client_error_forbidden, body.dump(), headers);
    }

    bool
    authorize_browser_request(resp_https_t response, req_https_t request) {
      const auto path = std::string_view { request->path };
      if (!path.starts_with("/api/") &&
          !path.starts_with("/steam-api/") &&
          !path.starts_with("/steam-store/")) {
        return true;
      }

      const auto origin = get_single_request_header(request, "origin");
      const auto referer = get_single_request_header(request, "referer");
      const auto fetch_site = get_single_request_header(request, "sec-fetch-site");
      const auto host = get_single_request_header(request, "host");
      const auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      if (!origin.valid || !referer.valid || !fetch_site.valid || !host.valid ||
          !http_util::browser_request_source_allowed(
            origin.value,
            referer.value,
            fetch_site.value,
            host.value.value_or(std::string_view {}),
            net::from_address(address) == net::PC
          )) {
        BOOST_LOG(debug) << "Web UI: rejected cross-site browser request to ["sv << request->path << ']';
        send_cross_site_forbidden(std::move(response));
        return false;
      }
      return true;
    }
  }  // namespace

  void
  send_unauthorized(resp_https_t response, req_https_t request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(error) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "WWW-Authenticate", R"(Basic realm="Sunshine Gamestream Host", charset="UTF-8")" }
    };
    response->write(SimpleWeb::StatusCode::client_error_unauthorized, headers);
  }

  /**
   * Logout endpoint: for localhost (PC) returns 200 so the browser does not show
   * a password dialog; for other allowed origins returns 401 with WWW-Authenticate
   * so the browser shows the credential prompt. Denied origins receive 403.
   */
  void
  handleLogout(resp_https_t response, req_https_t request) {
    if (!authorize_browser_request(response, request)) return;

    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    auto ip_type = net::from_address(address);

    if (ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- logout denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return;
    }

    if (ip_type == net::PC) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- logout (local), responding 200"sv;
      response->write(SimpleWeb::StatusCode::success_ok, "");
      return;
    }

    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- logout requested, responding 401"sv;
    send_unauthorized(response, request);
  }

  void
  send_redirect(resp_https_t response, req_https_t request, const char *path) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(error) << "Web UI: ["sv << address << "] -- not authorized, redirect"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "Location", path }
    };
    response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, headers);
  }

  bool
  authenticate(resp_https_t response, req_https_t request) {
    if (!authorize_browser_request(response, request)) return false;

    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    auto ip_type = net::from_address(address);

    if (ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return false;
    }

    // If credentials are shown, redirect the user to a /welcome page
    if (config::sunshine.username.empty()) {
      send_redirect(response, request, "/welcome");
      return false;
    }

    if (ip_type == net::PC) {
      return true;
    }

    auto fg = util::fail_guard([&]() {
      send_unauthorized(response, request);
    });

    auto auth = request->header.find("authorization");
    if (auth == request->header.end()) {
      return false;
    }

    auto &rawAuth = auth->second;
    constexpr auto basicPrefix = "Basic "sv;
    if (rawAuth.length() <= basicPrefix.length() || 
        rawAuth.substr(0, basicPrefix.length()) != basicPrefix) {
      return false;
    }
    
    std::string authData;
    try {
      authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr(basicPrefix.length()));
    }
    catch (const std::exception &e) {
      BOOST_LOG(debug) << "Authentication: Base64 decode failed: " << e.what();
      return false;
    }

    int index = authData.find(':');
    if (index >= authData.size() - 1) {
      return false;
    }

    auto username = authData.substr(0, index);
    auto password = authData.substr(index + 1);
    auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();

    if (!boost::iequals(username, config::sunshine.username) || hash != config::sunshine.password) {
      return false;
    }

    fg.disable();
    return true;
  }

  void
  not_found(resp_https_t response, req_https_t request) {
    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    response->write(data.str());

    *response << "HTTP/1.1 404 NOT FOUND\r\n"
              << data.str();
  }

  void
  close_connection(resp_https_t response, req_https_t request) {
      *response << "HTTP/1.1 444 No Response\r\n";
      response->close_connection_after_response = true;
      return;
  }

  void
  getHtmlPage(resp_https_t response, req_https_t request, const std::string& pageName, bool requireAuth = true) {
    if (requireAuth && !authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file((std::string(WEB_DIR) + pageName).c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    if (pageName == "apps.html") {
      headers.emplace("Access-Control-Allow-Origin", "https://images.igdb.com/");
    }
    response->write(content, headers);
  }

  void
  getIndexPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "index.html");
  }

  void
  getPinPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "pin.html");
  }

  void
  getAppsPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "apps.html");
  }

  void
  getClientsPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "clients.html");
  }

  void
  getConfigPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "config.html");
  }

  void
  getPasswordPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "password.html");
  }

  void
  getWelcomePage(resp_https_t response, req_https_t request) {
    // 如果已经有用户名，要求认证后才能访问（防止未授权访问）
    // 认证通过后重定向到首页，认证失败则拒绝访问
    if (!config::sunshine.username.empty()) {
      if (!authenticate(response, request)) {
        return; // authenticate已经发送了401响应
      }
      // 认证通过，重定向到首页
      send_redirect(response, request, "/");
      return;
    }
    // 只有在没有用户名时才显示welcome页面（首次设置）
    getHtmlPage(response, request, "welcome.html", false);
  }

  void
  getTroubleshootingPage(resp_https_t response, req_https_t request) {
    getHtmlPage(response, request, "troubleshooting.html");
  }

  /**
   * 处理静态资源文件
   */
  void
  getStaticResource(resp_https_t response, req_https_t request, const std::string& path, const std::string& contentType) {
    // print_req(request);

    std::ifstream in(file_handler::path_from_utf8(path), std::ios::binary);
    if (!in.is_open()) {
      BOOST_LOG(error) << "Failed to open Web UI resource: " << path;
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error);
      return;
    }
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", contentType);
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  void
  getFaviconImage(resp_https_t response, req_https_t request) {
    getStaticResource(response, request, WEB_DIR "images/sunshine.ico", "image/x-icon");
  }

  void
  getSunshineLogoImage(resp_https_t response, req_https_t request) {
    getStaticResource(response, request, WEB_DIR "images/logo-sunshine-256.png", "image/png");
  }

  void
  getAlkaidLabLogoImage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    getStaticResource(response, request, WEB_DIR "images/logo-alkaidlab.png", "image/png");
  }

  void
  getNatPierceLogoImage(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    getStaticResource(response, request, WEB_DIR "images/logo-natpierce.png", "image/png");
  }

  /**
   * @brief 检查 child 是否是 parent 目录的子路径（防止路径穿越）
   */
  bool
  isChildPath(fs::path const &child, fs::path const &parent) {
    auto relPath = fs::relative(child, parent);
    return *(relPath.begin()) != fs::path("..");
  }

  void
  getBoxArt(resp_https_t response, req_https_t request) {
    print_req(request);

    // Extract image filename from request path
    std::string path = request->path;
    if (path.find("/boxart/") == 0) {
      path = path.substr(8); // Remove "/boxart/" prefix
    }
    path = SimpleWeb::Percent::decode(path);

    BOOST_LOG(debug) << "getBoxArt: Requested file: " << path;

    static const fs::path assetsRoot = fs::weakly_canonical(file_handler::path_from_utf8(SUNSHINE_ASSETS_DIR));
    static const fs::path coversRoot = fs::weakly_canonical(platf::appdata() / "covers");

    // First try to find in SUNSHINE_ASSETS_DIR
    const auto requestedPath = file_handler::path_from_utf8(path);
    fs::path targetPath = fs::weakly_canonical(assetsRoot / requestedPath);
    fs::path finalPath;
    bool found = false;

    // Strict check: Allow only files directly in assets root, no subdirectories
    if (targetPath.parent_path() == assetsRoot && fs::exists(targetPath) && fs::is_regular_file(targetPath)) {
      finalPath = targetPath;
      found = true;
      BOOST_LOG(debug) << "Found in boxart: " << file_handler::path_to_utf8(finalPath);
    }
    
    // If not found in boxart, try covers directory
    if (!found) {
      targetPath = fs::weakly_canonical(coversRoot / requestedPath);
      // For covers, we use isChildPath which allows subdirectories but prevents traversal out of root
      if (isChildPath(targetPath, coversRoot) && fs::exists(targetPath) && fs::is_regular_file(targetPath)) {
        finalPath = targetPath;
        found = true;
        BOOST_LOG(debug) << "Found in covers: " << file_handler::path_to_utf8(finalPath);
      }
    }

    if (!found) {
      // If still not found or invalid path, use default image
      BOOST_LOG(debug) << "Not found or invalid path, using default box.png";
      finalPath = assetsRoot / "box.png";
      // Ensure default file exists, otherwise we might fail later
      if (!fs::exists(finalPath)) {
        BOOST_LOG(warning) << "Default box.png not found at: " << file_handler::path_to_utf8(finalPath);
        response->write(SimpleWeb::StatusCode::client_error_not_found, "Image not found");
        return;
      }
    }

    const auto imagePath = file_handler::path_to_utf8(finalPath);

    // Get file size
    std::error_code ec;
    auto fileSize = fs::file_size(finalPath, ec);
    if (ec) {
      BOOST_LOG(warning) << "Failed to get file size for: " << imagePath;
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to read image file");
      return;
    }

    // Determine Content-Type from file extension
    std::string ext = finalPath.extension().string();
    if (!ext.empty() && ext[0] == '.') {
      ext = ext.substr(1);
    }
    
    auto mimeType = mime_types.find(ext);
    std::string contentType = "image/png"; // Default type
    
    if (mimeType != mime_types.end()) {
      contentType = mimeType->second;
    }
    
    BOOST_LOG(debug) << "Serving boxart: " << imagePath << " (Content-Type: " << contentType << ", Size: " << fileSize << " bytes)";

    // Return image resource
    std::ifstream in(finalPath, std::ios::binary);
    if (!in.is_open()) {
      BOOST_LOG(warning) << "Failed to open image file: " << imagePath;
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to open image file");
      return;
    }

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", contentType);
    headers.emplace("Content-Length", std::to_string(fileSize));
    headers.emplace("Cache-Control", "max-age=3600"); // Add caching to reduce load
    
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  void
  getNodeModules(resp_https_t response, req_https_t request) {
    // print_req(request);
    fs::path webDirPath = file_handler::path_from_utf8(WEB_DIR);
    fs::path nodeModulesPath(webDirPath / "assets");

    // .relative_path is needed to shed any leading slash that might exist in the request path
    const auto decodedRequestPath = SimpleWeb::Percent::decode(request->path);
    auto filePath = fs::weakly_canonical(webDirPath / file_handler::path_from_utf8(decodedRequestPath).relative_path());

    // Don't do anything if file does not exist or is outside the assets directory
    if (!isChildPath(filePath, nodeModulesPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the assets folder";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Bad Request");
    }
    else if (!fs::exists(filePath) || !fs::is_regular_file(filePath)) {
      response->write(SimpleWeb::StatusCode::client_error_not_found);
    }
    else {
      auto relPath = fs::relative(filePath, webDirPath);
      // get the mime type from the file extension mime_types map
      // remove the leading period from the extension
      auto mimeType = mime_types.find(relPath.extension().string().substr(1));
      // check if the extension is in the map at the x position
      if (mimeType != mime_types.end()) {
        // if it is, set the content type to the mime type
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Content-Type", mimeType->second);
        std::ifstream in(filePath, std::ios::binary);
        if (!in.is_open()) {
          BOOST_LOG(error) << "Failed to open Web UI asset: " << file_handler::path_to_utf8(filePath);
          response->write(SimpleWeb::StatusCode::server_error_internal_server_error);
          return;
        }
        response->write(SimpleWeb::StatusCode::success_ok, in, headers);
      }
      // do not return any file if the type is not in the map
    }
  }

  void
  getApps(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(config::stream.file_apps.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(content, headers);
  }

  /**
   * @brief Snapshot of log cache state, swapped atomically via shared_ptr.
   */
  struct LogCacheSnapshot {
    std::shared_ptr<const std::string> content;  ///< Cached log content (nullptr in offset-only mode)
    std::uintmax_t file_size = 0;                ///< Actual file size on disk when snapshot was taken
    std::intmax_t mtime_ns = 0;                  ///< File mtime when snapshot was taken
    std::uintmax_t start_offset = 0;             ///< File byte position where content begins
  };

  /**
   * @brief Try to read only the new tail of the log file and append to existing content.
   * @return New content on success, nullptr on any failure (caller should fall back to full read).
   */
  static std::shared_ptr<const std::string> try_incremental_log_read(
    const std::filesystem::path &log_path,
    std::uintmax_t prev_size,
    std::uintmax_t current_size,
    const std::shared_ptr<const std::string> &old_content) {
    if (current_size <= prev_size || prev_size == 0 || !old_content) {
      return nullptr;
    }
    std::ifstream in(log_path, std::ios::binary);
    if (!in || !in.seekg(static_cast<std::streamoff>(prev_size))) {
      return nullptr;
    }
    const auto tail_len = current_size - prev_size;
    std::string tail(tail_len, '\0');
    if (!in.read(tail.data(), static_cast<std::streamsize>(tail_len))) {
      return nullptr;
    }
    return std::make_shared<const std::string>(*old_content + tail);
  }

  /**
   * @brief Read a specific byte range [offset, offset+length) from a file.
   * @return Content string on success, nullptr on failure.
   */
  static std::shared_ptr<const std::string>
  read_file_range(const std::filesystem::path &path, std::uintmax_t offset, std::uintmax_t length) {
    std::ifstream in(path, std::ios::binary);
    if (!in || !in.seekg(static_cast<std::streamoff>(offset))) {
      return nullptr;
    }
    std::string content(static_cast<std::size_t>(length), '\0');
    if (!in.read(content.data(), static_cast<std::streamsize>(length))) {
      return nullptr;
    }
    return std::make_shared<const std::string>(std::move(content));
  }

  /**
   * @brief Get the logs from the log file.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * Dual mode via X-Log-Offset header:
   *   - Without header: stream full log file from disk (for download)
   *   - With header:    cached or offset-based incremental support (for live viewer)
   *
   * When the log file is small (≤ 4 MB), the entire file is cached in memory for fast serving.
   * When the log file exceeds 4 MB, no content is cached; reads go directly to disk at the
   * client's offset (offset-only mode), avoiding unbounded memory growth.
   *
   * @api_examples{/api/logs| GET| null}
   */
  void
  getLogs(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) {
      return;
    }

    //print_req(request);

    const auto log_path = file_handler::path_from_utf8(config::sunshine.log_file);

    // --- Mode 1: No X-Log-Offset header → stream full file from disk (download) ---
    auto offset_it = request->header.find("X-Log-Offset");
    if (offset_it == request->header.end()) {
      std::ifstream in(log_path, std::ios::binary);
      if (!in.is_open()) {
        response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to open log file");
        return;
      }
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", "text/plain; charset=utf-8");
      headers.emplace("Content-Disposition", "attachment; filename=\"sunshine.log\"");
      // Omit Content-Length: log file is actively written (TOCTOU risk)
      response->write(SimpleWeb::StatusCode::success_ok, in, headers);
      return;
    }

    // --- Mode 2: X-Log-Offset present → cached or offset-only mode for live viewer ---

    // When file ≤ MAX_LOG_CACHE_SIZE: cached in memory.  Otherwise: disk reads only.
    static constexpr std::uintmax_t MAX_LOG_CACHE_SIZE = 4 * 1024 * 1024;   // 4 MB
    static constexpr std::uintmax_t MAX_RESPONSE_SIZE  = 4 * 1024 * 1024;   // 4 MB

    static std::atomic<std::shared_ptr<const LogCacheSnapshot>> log_cache;

    // Check file status
    std::error_code ec;
    auto current_size = std::filesystem::file_size(log_path, ec);
    if (ec) {
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to read log file");
      return;
    }
    auto current_mtime = std::filesystem::last_write_time(log_path, ec);
    if (ec) {
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to read log file");
      return;
    }
    auto current_mtime_ns = current_mtime.time_since_epoch().count();

    // Refresh cache if file changed
    auto snapshot = log_cache.load();
    const bool cache_stale = !snapshot || current_size != snapshot->file_size || current_mtime_ns != snapshot->mtime_ns;
    if (cache_stale) {
      auto new_snap = std::make_shared<LogCacheSnapshot>();
      new_snap->file_size = current_size;
      new_snap->mtime_ns = current_mtime_ns;

      if (current_size <= MAX_LOG_CACHE_SIZE) {
        // --- Cached mode: file fits in memory ---
        std::shared_ptr<const std::string> new_content;
        if (snapshot && snapshot->content && snapshot->file_size > 0 && current_size > snapshot->file_size) {
          new_content = try_incremental_log_read(log_path, snapshot->file_size, current_size, snapshot->content);
        }
        if (!new_content) {
          // Use sampled current_size to avoid TOCTOU unsigned underflow at start_offset
          auto read_len = std::min(current_size, MAX_LOG_CACHE_SIZE);
          auto read_start = current_size - read_len;
          new_content = read_file_range(log_path, read_start, read_len);
        }
        if (!new_content) {
          if (current_size > 0) {
            response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to read log file");
            return;
          }
          new_content = std::make_shared<const std::string>();
        }
        new_snap->content = std::move(new_content);
        new_snap->start_offset = current_size - new_snap->content->size();
      }
      else {
        // --- Offset-only mode: file too large, don't cache content ---
        new_snap->content = nullptr;
        new_snap->start_offset = 0;
      }

      // CAS publish: avoid overwriting a newer snapshot from a concurrent thread
      if (!log_cache.compare_exchange_strong(snapshot, new_snap)) {
        // CAS failed: snapshot already updated by compare_exchange_strong
      }
      else {
        snapshot = std::move(new_snap);
      }
    }

    // Parse client offset
    std::uintmax_t client_offset = 0;
    try {
      std::string offset_str(offset_it->second);
      boost::algorithm::trim(offset_str);
      if (!offset_str.empty()) {
        client_offset = std::stoull(offset_str);
      }
    }
    catch (const std::invalid_argument &) {
      client_offset = 0;
    }
    catch (const std::out_of_range &) {
      client_offset = 0;
    }

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/plain");
    headers.emplace("X-Log-Size", std::to_string(snapshot->file_size));
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    // No change in logs → 304
    if (client_offset > 0 && client_offset == snapshot->file_size) {
      headers.emplace("X-Log-Range", "unchanged");
      response->write(SimpleWeb::StatusCode::redirection_not_modified, headers);
      return;
    }

    if (snapshot->content) {
      // === Cached mode: serve from memory ===
      if (client_offset > 0 && client_offset >= snapshot->start_offset && client_offset < snapshot->file_size) {
        auto cache_pos = client_offset - snapshot->start_offset;
        headers.emplace("X-Log-Range", "incremental");
        auto delta = snapshot->content->substr(static_cast<std::size_t>(cache_pos));
        response->write(SimpleWeb::StatusCode::success_ok, delta, headers);
      }
      else {
        headers.emplace("X-Log-Range", "full");
        response->write(SimpleWeb::StatusCode::success_ok, *snapshot->content, headers);
      }
    }
    else {
      // === Offset-only mode: read from disk, bounded by snapshot->file_size ===
      if (client_offset > 0 && client_offset < snapshot->file_size) {
        auto delta_size = snapshot->file_size - client_offset;
        if (delta_size <= MAX_RESPONSE_SIZE) {
          auto data = read_file_range(log_path, client_offset, delta_size);
          if (data) {
            headers.emplace("X-Log-Range", "incremental");
            response->write(SimpleWeb::StatusCode::success_ok, *data, headers);
            return;
          }
        }
      }
      // Delta too large, read failed, or first request: return tail up to snapshot->file_size
      auto tail_len = std::min(snapshot->file_size, MAX_RESPONSE_SIZE);
      auto tail_start = snapshot->file_size - tail_len;
      auto tail = read_file_range(log_path, tail_start, tail_len);
      if (!tail) {
        response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Failed to read log file");
        return;
      }
      headers.emplace("X-Log-Range", "full");
      response->write(SimpleWeb::StatusCode::success_ok, *tail, headers);
    }
  }

  void
  saveApp(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    // Prevent concurrent write to file_apps causing file corruption
    bool expected = false;
    if (!apps_writing.compare_exchange_strong(expected, true)) {
      pt::ptree outputTree;
      outputTree.put("status", "false");
      outputTree.put("error", "Another save operation is in progress");
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(SimpleWeb::StatusCode::client_error_conflict, data.str());
      return;
    }
    auto writing_guard = util::fail_guard([]() { apps_writing = false; });

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    pt::ptree inputTree, fileTree;

    try {
      pt::read_json(ss, inputTree);
      file_handler::read_json(config::stream.file_apps, fileTree);

      auto &apps_node = fileTree.get_child("apps"s);
      auto &input_apps_node = inputTree.get_child("apps"s);
      auto &input_edit_node = inputTree.get_child("editApp"s);

      const auto normalize_gamepad = [&](pt::ptree &app_node) {
        auto gamepad = app_node.get_optional<std::string>("gamepad");
        if (gamepad && gamepad->empty()) {
          app_node.erase("gamepad");
        }
        else if (gamepad && *gamepad != "auto"sv && *gamepad != "x360"sv && *gamepad != "ds4"sv && *gamepad != "ds5"sv) {
          outputTree.put("status", "false");
          outputTree.put("error", "Invalid per-app gamepad type");
          return false;
        }

        return true;
      };

      for (auto &[_, app_node] : input_apps_node) {
        if (!normalize_gamepad(app_node)) {
          return;
        }
      }

      // Validate app name when editing a specific app
      if (!input_edit_node.empty()) {
        auto app_name = input_edit_node.get<std::string>("name", "");
        if (app_name.empty() || app_name.size() > 256) {
          outputTree.put("status", "false");
          outputTree.put("error", "App name must be 1-256 characters");
          return;
        }
      }

      if (input_edit_node.empty()) {
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", input_apps_node));
      }
      else {
        auto prep_cmd = input_edit_node.get_child_optional("prep-cmd");
        if (prep_cmd && prep_cmd->empty()) {
          input_edit_node.erase("prep-cmd");
        }

        auto detached = input_edit_node.get_child_optional("detached");
        if (detached && detached->empty()) {
          input_edit_node.erase("detached");
        }

        if (!normalize_gamepad(input_edit_node)) {
          return;
        }

        int index = input_edit_node.get<int>("index");
        input_edit_node.erase("index");

        if (index == -1) {
          apps_node.push_back(std::make_pair("", input_edit_node));
        }
        else {
          // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
          pt::ptree newApps;
          int i = 0;
          for (auto &[_, app_node] : input_apps_node) {
            newApps.push_back(std::make_pair("", i == index ? input_edit_node : app_node));
            i++;
          }
          fileTree.erase("apps");
          fileTree.push_back(std::make_pair("apps", newApps));
        }
      }

      file_handler::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveApp: "sv << e.what();

      outputTree.put("status", "false");
      outputTree.put("error", "Invalid Input JSON");
      return;
    }

    BOOST_LOG(info) << "SaveApp: configuration saved successfully"sv;
    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  void
  deleteApp(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    // Prevent concurrent write to file_apps causing file corruption
    bool expected = false;
    if (!apps_writing.compare_exchange_strong(expected, true)) {
      pt::ptree outputTree;
      outputTree.put("status", "false");
      outputTree.put("error", "Another operation is in progress");
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(SimpleWeb::StatusCode::client_error_conflict, data.str());
      return;
    }
    auto writing_guard = util::fail_guard([]() { apps_writing = false; });

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    pt::ptree fileTree;
    try {
      file_handler::read_json(config::stream.file_apps, fileTree);
      auto &apps_node = fileTree.get_child("apps"s);
      int index = stoi(request->path_match[1]);

      int apps_count = static_cast<int>(apps_node.size());
      if (index < 0 || index >= apps_count) {
        outputTree.put("status", "false");
        outputTree.put("error", "Invalid Index");
        return;
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i++ != index) {
            newApps.push_back(std::make_pair("", kv.second));
          }
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      file_handler::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "DeleteApp: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid File JSON");
      return;
    }

    BOOST_LOG(info) << "DeleteApp: configuration deleted successfully"sv;
    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  /**
   * @brief Delete multiple apps in a single atomic operation.
   *
   * Expects JSON body: {"indices":[<int>, <int>, ...]}
   *
   * Rationale: clients that want to delete N apps cannot just loop on
   * DELETE /api/apps/{id} — each successful delete shifts the remaining
   * indices, and a second concurrent caller is rejected by apps_writing.
   * By taking the lock once and rebuilding the array under it, we avoid both
   * problems: indices are interpreted against a single snapshot, the JSON file
   * is rewritten once, and proc::refresh runs only once.
   *
   * Response:
   *   200 {"status":"true",  "deleted":<N>, "remaining":<M>}
   *   400 {"status":"false", "error":"..."} for content-type / JSON / index /
   *        file-write business errors. Follows uploadCover() convention in
   *        this same file (status code derived from presence of 'error' key
   *        inside the fail_guard).
   *   401  not authenticated (via authenticate)
   *   409  another apps-writer is already in flight
   *
   * @api_examples{/api/apps/batch-delete| POST| {"indices":[2,5,7]}}
   */
  void
  batchDeleteApps(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    // Same single-writer guard as deleteApp / saveApp.
    bool expected = false;
    if (!apps_writing.compare_exchange_strong(expected, true)) {
      pt::ptree busy;
      busy.put("status", "false");
      busy.put("error", "Another operation is in progress");
      std::ostringstream data;
      pt::write_json(data, busy);
      response->write(SimpleWeb::StatusCode::client_error_conflict, data.str());
      return;
    }
    auto writing_guard = util::fail_guard([]() { apps_writing = false; });

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      // Mirror uploadCover's convention in this file: when fail_guard fires
      // with an 'error' field, emit 4xx so clients can distinguish business
      // failures from success rather than parsing status:"false" out of a 200.
      SimpleWeb::StatusCode code = SimpleWeb::StatusCode::success_ok;
      if (outputTree.get_child_optional("error").has_value()) {
        code = SimpleWeb::StatusCode::client_error_bad_request;
      }
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(code, data.str());
    });

    std::stringstream ss;
    ss << request->content.rdbuf();

    std::set<int> indices_to_remove;
    try {
      pt::ptree body;
      pt::read_json(ss, body);

      auto indices_node = body.get_child_optional("indices");
      if (!indices_node) {
        outputTree.put("status", "false");
        outputTree.put("error", "Missing 'indices' array");
        return;
      }

      if (indices_node->size() > 1024) {
        outputTree.put("status", "false");
        outputTree.put("error", "Too many indices in a single request");
        return;
      }
      for (const auto &kv : *indices_node) {
        // boost::property_tree json reader stores array values as anonymous
        // children with empty keys. get_value<int>() will throw if the value
        // is not parseable as an integer.
        int idx = kv.second.get_value<int>();
        indices_to_remove.insert(idx);
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "BatchDeleteApps: invalid JSON body: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid JSON body");
      return;
    }

    pt::ptree fileTree;
    try {
      file_handler::read_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "BatchDeleteApps: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid File JSON");
      return;
    }

    // Validate every index against the single snapshot we just loaded BEFORE
    // any write, so a partially invalid request fails atomically.
    const int apps_count = static_cast<int>(fileTree.get_child("apps"s).size());
    for (int idx : indices_to_remove) {
      if (idx < 0 || idx >= apps_count) {
        outputTree.put("status", "false");
        outputTree.put("error", "Invalid Index");
        return;
      }
    }

    // Empty selection: success no-op. Skip the write+refresh, but still emit
    // 'remaining' so the success contract matches the non-empty path.
    if (indices_to_remove.empty()) {
      outputTree.put("status", "true");
      outputTree.put("deleted", 0);
      outputTree.put("remaining", apps_count);
      return;
    }

    int deleted_count = 0;
    int remaining_count = 0;
    try {
      auto &apps_node = fileTree.get_child("apps"s);
      pt::ptree newApps;
      int i = 0;
      for (const auto &kv : apps_node) {
        if (indices_to_remove.find(i) == indices_to_remove.end()) {
          newApps.push_back(std::make_pair("", kv.second));
        }
        else {
          ++deleted_count;
        }
        ++i;
      }
      remaining_count = static_cast<int>(newApps.size());
      fileTree.erase("apps");
      fileTree.push_back(std::make_pair("apps", newApps));

      file_handler::write_json(config::stream.file_apps, fileTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "BatchDeleteApps: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid File JSON");
      return;
    }

    BOOST_LOG(info) << "BatchDeleteApps: removed "sv << deleted_count
                    << " app(s), "sv << remaining_count << " remaining"sv;
    outputTree.put("status", "true");
    outputTree.put("deleted", deleted_count);
    outputTree.put("remaining", remaining_count);
    proc::refresh(config::stream.file_apps);
  }

  void
  uploadCover(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      SimpleWeb::StatusCode code = SimpleWeb::StatusCode::success_ok;
      if (outputTree.get_child_optional("error").has_value()) {
        code = SimpleWeb::StatusCode::client_error_bad_request;
      }

      pt::write_json(data, outputTree);
      response->write(code, data.str());
    });
    pt::ptree inputTree;
    try {
      pt::read_json(ss, inputTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "UploadCover: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }

    auto key = inputTree.get("key", "");
    if (key.empty()) {
      outputTree.put("error", "Cover key is required");
      return;
    }
    auto url = inputTree.get("url", "");

    const std::string coverdir = file_handler::path_to_utf8(platf::appdata() / "covers");
    file_handler::make_directory(coverdir);

    const auto cover_path = file_handler::path_from_utf8(coverdir) / (http::url_escape(key) + ".png");
    const std::string path = file_handler::path_to_utf8(cover_path);
    if (!url.empty()) {
      if (!http::download_public_cover_image(url, path)) {
        outputTree.put("error", "Failed to download public HTTPS cover");
        return;
      }
    }
    else {
      // Limit base64 data size to prevent memory exhaustion
      // (10MB decoded to about 7.5MB, enough for cover images)
      constexpr std::size_t MAX_COVER_BASE64_SIZE = 10 * 1024 * 1024;
      auto base64_str = inputTree.get<std::string>("data");
      if (base64_str.size() > MAX_COVER_BASE64_SIZE) {
        outputTree.put("error", "Cover image too large (max 10MB)");
        return;
      }
      auto data = SimpleWeb::Crypto::Base64::decode(base64_str);

      std::ofstream imgfile(file_handler::path_from_utf8(path), std::ios::binary);
      if (!imgfile.is_open()) {
        outputTree.put("error", "Failed to create file");
        return;
      }
      imgfile.write(data.data(), (int) data.size());
      imgfile.close();
      
      if (imgfile.fail()) {
        outputTree.put("error", "Failed to write file");
        return;
      }
    }
    outputTree.put("path", path);
  }

  void
  getConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    auto devices { display_device::enum_available_devices() };
    pt::ptree devices_nodes;
    for (const auto &[device_id, data] : devices) {
      pt::ptree devices_node;
      devices_node.put("device_id"s, device_id);
      devices_node.put("data"s, to_string(data));
      devices_nodes.push_back(std::make_pair(""s, devices_node));
    }

    auto adapters { platf::adapter_names() };
    pt::ptree adapters_nodes;
    for (const auto &adapter_name : adapters) {
      pt::ptree adapters_node;
      adapters_node.put("name"s, adapter_name);
      adapters_nodes.push_back(std::make_pair(""s, adapters_node));
    }

    outputTree.add_child("display_devices", devices_nodes);
    outputTree.add_child("adapters", adapters_nodes);
    outputTree.put("status", "true");
    outputTree.put("platform", SUNSHINE_PLATFORM);
    outputTree.put("version", PROJECT_VER);

    auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));
    for (auto &[name, value] : vars) {
      // widget_token 是本地端点凭证,不回显明文;只暴露是否已配置
      if (name == "widget_token") {
        continue;
      }
      outputTree.put(std::move(name), std::move(value));
    }
    outputTree.put("widget_token_configured", !config::sunshine.widget_token.empty());

    outputTree.put("active_encoder", video::active_encoder_name());
    if (auto frame_budget = nvenc::get_frame_budget_report()) {
      pt::ptree budget_node;
      budget_node.put("clamped", frame_budget->clamped);
      budget_node.put("configured_preset", frame_budget->configured_preset);
      budget_node.put("effective_preset", frame_budget->effective_preset);
      budget_node.put("width", frame_budget->width);
      budget_node.put("height", frame_budget->height);
      budget_node.put("fps", frame_budget->fps);
      budget_node.put("budget_ms", frame_budget->budget_ms);
      budget_node.put("estimated_ms", frame_budget->estimated_ms);
      budget_node.put("configured_estimated_ms", frame_budget->configured_estimated_ms);
      budget_node.put("num_engines", frame_budget->num_engines);
      outputTree.add_child("active_nvenc_frame_budget", budget_node);
    }
    // Configuration capability only; never expose the paired-client tunnel token here.
    outputTree.put("usb_forwarding_config_version", "1");
    outputTree.put("pair_name", nvhttp::get_pair_name());
  }

  void
  getLocale(resp_https_t response, req_https_t request) {
    // we need to return the locale whether authenticated or not

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    outputTree.put("status", "true");
    outputTree.put("locale", config::sunshine.locale);
  }

  std::vector<std::string>
  split(const std::string &str, char delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != std::string::npos) {
      tokens.push_back(str.substr(start, end - start));
      start = end + 1;
    }
    tokens.push_back(str.substr(start));
    return tokens;
  }

  bool
  saveVddSettings(std::string resArray, std::string fpsArray, std::string gpu_name) {
    pt::ptree iddOptionTree;
    pt::ptree global_node;
    pt::ptree resolutions_nodes;

    // prepare resolutions setting for vdd
    boost::regex pattern("\\[|\\]|\\s+");
    char delimiter = ',';

    // 添加全局刷新率到global节点
    for (const auto &fps : split(boost::regex_replace(fpsArray, pattern, ""), delimiter)) {
      global_node.add("g_refresh_rate", fps);
    }

    std::string str = boost::regex_replace(resArray, pattern, "");
    boost::algorithm::trim(str);
    for (const auto &resolution : split(str, delimiter)) {
      auto index = resolution.find('x');
      if(index == std::string::npos) {
        return false;
      }
      pt::ptree res_node;
      res_node.put("width", resolution.substr(0, index));
      res_node.put("height", resolution.substr(index + 1));
      resolutions_nodes.push_back(std::make_pair("resolution"s, res_node));
    }

    // 类似于 config.cpp 中的 path_f 函数逻辑，使用相对路径
    std::filesystem::path idd_option_path = platf::appdata() / "vdd_settings.xml";

    BOOST_LOG(info) << "VDD配置文件路径: " << file_handler::path_to_utf8(idd_option_path);

    if (!fs::exists(idd_option_path)) {
        return false;
    }

    // 先读取现有配置文件
    pt::ptree existing_root;
    pt::ptree root;

    try {
      {
        std::ifstream input(idd_option_path, std::ios::binary);
        if (!input.is_open()) {
          throw std::runtime_error("Unable to open VDD configuration file");
        }
        pt::read_xml(input, existing_root);
      }
      // 如果现有配置文件中已有vdd_settings节点
      if (existing_root.get_child_optional("vdd_settings")) {
        // 复制现有配置
        iddOptionTree = existing_root.get_child("vdd_settings");

        // 更新需要更改的部分
        pt::ptree monitor_node;
        monitor_node.put("count", 1);

        pt::ptree gpu_node;
        gpu_node.put("friendlyname", gpu_name.empty() ? "default" : gpu_name);

        // 替换配置
        iddOptionTree.put_child("monitors", monitor_node);
        iddOptionTree.put_child("gpu", gpu_node);
        iddOptionTree.put_child("global", global_node);
        iddOptionTree.put_child("resolutions", resolutions_nodes);
      } else {
        // 如果没有vdd_settings节点，创建新的
        pt::ptree monitor_node;
        monitor_node.put("count", 1);

        pt::ptree gpu_node;
        gpu_node.put("friendlyname", gpu_name.empty() ? "default" : gpu_name);

        iddOptionTree.add_child("monitors", monitor_node);
        iddOptionTree.add_child("gpu", gpu_node);
        iddOptionTree.add_child("global", global_node);
        iddOptionTree.add_child("resolutions", resolutions_nodes);
      }
    } catch(std::exception &e) {
      // 读取失败，创建新的配置
      BOOST_LOG(warning) << "读取现有VDD配置失败，创建新配置: " << e.what();

      pt::ptree monitor_node;
      monitor_node.put("count", 1);

      pt::ptree gpu_node;
      gpu_node.put("friendlyname", gpu_name.empty() ? "default" : gpu_name);

      iddOptionTree.add_child("monitors", monitor_node);
      iddOptionTree.add_child("gpu", gpu_node);
      iddOptionTree.add_child("global", global_node);
      iddOptionTree.add_child("resolutions", resolutions_nodes);
    }

    root.add_child("vdd_settings", iddOptionTree);
    try {
      // 使用更紧凑的XML格式设置，减少不必要的空白
      auto setting = boost::property_tree::xml_writer_make_settings<std::string>(' ', 2);
      std::ostringstream oss;
      write_xml(oss, root, setting);

      // 清理多余空行，保持XML格式整洁
      std::string xml_content = oss.str();
      boost::regex empty_lines_regex("\\n\\s*\\n");
      xml_content = boost::regex_replace(xml_content, empty_lines_regex, "\n");

      std::ofstream file(idd_option_path);
      if (!file.is_open()) {
        throw std::runtime_error("Unable to open VDD configuration file");
      }
      file << xml_content;
      file.flush();
      if (!file) {
        throw std::runtime_error("Unable to write VDD configuration file");
      }

      return true;
    }
    catch(std::exception &e) {
      BOOST_LOG(warning) << "写入VDD配置失败: " << e.what();
      return false;
    }
  }

  void
  write_runtime_error(resp_https_t response, SimpleWeb::StatusCode http_status, int status_code, const std::string &status_message);

  bool
  require_localhost(resp_https_t response, req_https_t request, const std::string &action);


  void
  saveConfig(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    pt::ptree inputTree;

    try {
      pt::read_json(ss, inputTree);
      std::string resArray = inputTree.get<std::string>("resolutions", "[]");
      std::string fpsArray = inputTree.get<std::string>("fps", "[]");
      std::string gpu_name = inputTree.get<std::string>("adapter_name", "");

      // Validate config field lengths to prevent abuse
      auto sunshine_name = inputTree.get<std::string>("sunshine_name", "");
      if (sunshine_name.size() > 256) {
        outputTree.put("status", "false");
        outputTree.put("error", "sunshine_name too long (max 256)");
        return;
      }
      if (gpu_name.size() > 256) {
        outputTree.put("status", "false");
        outputTree.put("error", "adapter_name too long (max 256)");
        return;
      }

      saveVddSettings(resArray, fpsArray, gpu_name);

      // 将 inputTree 转换为 std::map（保证有序）
      std::map<std::string, std::string> fullConfig;
      for (const auto &kv : inputTree) {
        if (kv.first == "usb_forwarding_config_version") continue;
        std::string value = inputTree.get<std::string>(kv.first);
        fullConfig[kv.first] = value;
      }

      // 更新配置
      if (!config::update_full_config(fullConfig)) {
        outputTree.put("status", "false");
        outputTree.put("error", "failed to persist configuration");
        return;
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveConfig: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }

    outputTree.put("status", "true");
  }

  void
  getGamepadConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    pt::ptree outputTree;
    auto response_guard = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    const auto config_snapshot = config::get_config_snapshot();
    if (!config_snapshot) {
      outputTree.put("status", "false");
      outputTree.put("error", "failed to read controller configuration");
      return;
    }

    const auto get_value = [&](std::string_view key, std::string_view fallback) {
      const auto entry = config_snapshot->find(std::string {key});
      return entry == config_snapshot->end() ? std::string {fallback} : entry->second;
    };
    outputTree.put("status", "true");
    outputTree.put("gamepad", get_value("gamepad", "auto"));
    outputTree.put("motion_as_ds4", get_value("motion_as_ds4", "true"));
    outputTree.put("touchpad_as_ds4", get_value("touchpad_as_ds4", "true"));
    outputTree.put("ds4_back_as_touchpad_click", get_value("ds4_back_as_touchpad_click", "true"));
    outputTree.put("enable_dsu_server", get_value("enable_dsu_server", "false"));
    outputTree.put("dsu_server_port", get_value("dsu_server_port", "26760"));
  }

  void
  saveGamepadConfig(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    pt::ptree outputTree;
    auto response_guard = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      pt::ptree inputTree;
      std::stringstream body;
      body << request->content.rdbuf();
      pt::read_json(body, inputTree);
      if (inputTree.empty() || inputTree.size() > 6) {
        throw std::invalid_argument("controller configuration patch must contain 1 to 6 fields");
      }

      const std::set<std::string> boolean_fields {
        "ds4_back_as_touchpad_click",
        "enable_dsu_server",
        "motion_as_ds4",
        "touchpad_as_ds4",
      };
      std::map<std::string, std::string> updates;
      for (const auto &[key, node] : inputTree) {
        if (!node.empty()) {
          throw std::invalid_argument("controller configuration fields must be scalar values");
        }
        const auto value = node.get_value<std::string>();
        if (key == "gamepad") {
          if (value != "auto"sv && value != "x360"sv && value != "ds4"sv && value != "ds5"sv) {
            throw std::invalid_argument("invalid gamepad mode");
          }
        }
        else if (boolean_fields.contains(key)) {
          if (value != "true"sv && value != "false"sv) {
            throw std::invalid_argument("controller boolean fields must be true or false");
          }
        }
        else if (key == "dsu_server_port") {
          std::size_t parsed = 0;
          const auto port = std::stoi(value, &parsed);
          if (parsed != value.size() || port < 1024 || port > 65535) {
            throw std::invalid_argument("DSU port must be between 1024 and 65535");
          }
        }
        else {
          throw std::invalid_argument("unsupported controller configuration field");
        }
        if (!updates.emplace(key, value).second) {
          throw std::invalid_argument("duplicate controller configuration field");
        }
      }

      if (!config::update_config(updates)) {
        outputTree.put("status", "false");
        outputTree.put("error", "failed to persist controller configuration");
        return;
      }
      outputTree.put("status", "true");
    }
    catch (const std::exception &e) {
      BOOST_LOG(warning) << "SaveGamepadConfig: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "invalid controller configuration patch");
    }
  }

  void
  getImageEnhancementConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request) || !require_localhost(response, request, "Image enhancement configuration")) return;
    image_enhancement::api::get_config(response);
  }

  void
  saveImageEnhancementConfig(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request) || !require_localhost(response, request, "Image enhancement configuration")) return;
    image_enhancement::api::save_config(response, request);
  }

  void
  getImageEnhancementStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request) || !require_localhost(response, request, "Image enhancement status")) return;
    image_enhancement::api::get_status(response);
  }

  void
  getEnhancementSessions(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request) || !require_localhost(response, request, "Session image enhancement")) return;
    image_enhancement::api::get_sessions(response);
  }

  void
  setSessionNr(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request) || !require_localhost(response, request, "Session image enhancement")) return;
    image_enhancement::api::set_session_nr(response, request);
  }

  void
  rememberSessionNr(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request) || !require_localhost(response, request, "Session image enhancement")) return;
    image_enhancement::api::remember_session_nr(response, request);
  }

  void
  maintainImageEnhancementComponent(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request) || !require_localhost(response, request, "Image enhancement maintenance")) return;
    image_enhancement::api::maintenance(response, request);
  }

  void
  saveClients(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    nlohmann::json output {
      {"status", false},
    };

    try {
      std::stringstream body;
      body << request->content.rdbuf();
      const auto input = nlohmann::json::parse(body.str());
      if (!input.is_object()) {
        throw std::invalid_argument("clients must be a serialized JSON array");
      }
      const auto clients_it = input.find("clients");
      if (clients_it == input.end() || !clients_it->is_string()) {
        throw std::invalid_argument("clients must be a serialized JSON array");
      }

      const auto serialized_clients = clients_it->get<std::string>();
      constexpr std::size_t max_clients_config_size { 1024 * 1024 };
      if (serialized_clients.size() > max_clients_config_size) {
        throw std::invalid_argument("clients configuration is too large");
      }

      const auto clients = nlohmann::json::parse(serialized_clients);
      if (!clients.is_array()) {
        throw std::invalid_argument("clients must contain a JSON array");
      }
      if (clients.size() > 1024) {
        throw std::invalid_argument("too many client settings");
      }

      std::set<std::string> uuids;
      for (const auto &client : clients) {
        if (!client.is_object()) {
          throw std::invalid_argument("each client setting must be an object");
        }

        if (const auto uuid_it = client.find("uuid"); uuid_it != client.end()) {
          if (!uuid_it->is_string() || uuid_it->get_ref<const std::string &>().size() > 128) {
            throw std::invalid_argument("client uuid must be a string of at most 128 bytes");
          }
          const auto &uuid = uuid_it->get_ref<const std::string &>();
          if (!uuid.empty() && !uuids.insert(uuid).second) {
            throw std::invalid_argument("client uuid must be unique");
          }
        }

        if (const auto name_it = client.find("name"); name_it != client.end() &&
            (!name_it->is_string() || name_it->get_ref<const std::string &>().size() > 256)) {
          throw std::invalid_argument("client name must be a string of at most 256 bytes");
        }

        if (const auto profile_it = client.find("hdrProfile"); profile_it != client.end()) {
          if (!profile_it->is_string()) {
            throw std::invalid_argument("HDR profile must be a string");
          }
          const auto &profile = profile_it->get_ref<const std::string &>();
          if (!profile.empty() && !display_device::color_profile::is_valid_profile_basename(profile)) {
            throw std::invalid_argument("HDR profile must be an installed .icc or .icm filename");
          }
        }

        const auto brightness_mode = client.value("hdrBrightnessMode", "auto");
        if (brightness_mode != "auto" && brightness_mode != "manual") {
          throw std::invalid_argument("HDR brightness mode must be auto or manual");
        }
        if (brightness_mode == "manual") {
          const auto read_brightness = [&](const char *field) -> float {
            const auto value = client.find(field);
            if (value == client.end() || !value->is_number()) {
              throw std::invalid_argument(std::string { "manual HDR brightness requires numeric " } + field);
            }
            const float number = value->get<float>();
            if (!std::isfinite(number)) {
              throw std::invalid_argument(std::string { field } + " must be finite");
            }
            return number;
          };

          const auto validated = hdr::validate_client_display_capabilities(
            read_brightness("hdrBrightnessMaxNits"),
            read_brightness("hdrBrightnessMinNits"),
            read_brightness("hdrBrightnessMaxFullFrameNits"));
          if (!validated.capabilities.reported) {
            throw std::invalid_argument(validated.fallback_reason);
          }
        }
      }

      if (!config::save_clients_config(serialized_clients)) {
        output["error"] = "failed to persist client settings";
      }
      else {
        output["status"] = true;
      }
    }
    catch (const std::exception &e) {
      BOOST_LOG(warning) << "SaveClients: "sv << e.what();
      output["error"] = e.what();
    }

    send_response(response, output);
  }

  void
  getWebhookConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    webhook::api::get_config(std::move(response), config::sunshine.config_file);
  }

  void
  saveWebhookConfig(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    webhook::api::save_config(
      std::move(response),
      std::move(request),
      config::sunshine.config_file
    );
  }

  void
  testWebhook(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    webhook::api::test_delivery(std::move(response), std::move(request));
  }

#ifdef _WIN32
  void
  getDualSenseConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    ds5_config::api::get_config(std::move(response), config::sunshine.config_file);
  }

  void
  saveDualSenseConfig(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;
    ds5_config::api::save_config(
      std::move(response),
      std::move(request),
      config::sunshine.config_file
    );
  }
#endif

  void
  restart(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    // We may not return from this call
    platf::restart();
  }

  void
  boom(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);
    if (GetConsoleWindow() == NULL) {
      lifetime::exit_sunshine(ERROR_SHUTDOWN_IN_PROGRESS, true);
      return;
    }
    lifetime::exit_sunshine(0, true);
  }

  void
  resetDisplayDevicePersistence(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    display_device::session_t::get().reset_persistence();
    outputTree.put("status", true);
  }

  void
  testMicrophone(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

#ifdef _WIN32
    const auto result = platf::audio::test_mic_redirect();
    send_response(response, nlohmann::json {
      {"success", result.success},
      {"error_code", result.error_code},
      {"backend", result.backend},
    });
#else
    send_response(response, nlohmann::json {
      {"success", false},
      {"error_code", "MIC_TEST_UNSUPPORTED"},
    });
#endif
  }

  void
  getMicrophoneStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

#ifdef _WIN32
    const auto status = platf::audio::mic_redirect_status();
    send_response(response, nlohmann::json {
      {"success", true},
      {"configured_backend", status.configured_backend},
      {"active_backend", status.active_backend},
      {"fallback_reason", status.fallback_reason},
      {"component_available", status.component_available},
      {"online", status.online},
      {"device_created", status.device_created},
      {"host_streaming", status.host_streaming},
      {"generation", status.generation},
      {"state", status.state},
      {"buffered_bytes", status.buffered_bytes},
      {"underruns", status.underruns},
      {"dropped_frames", status.dropped_frames},
      {"submit_errors", status.submit_errors},
      {"last_error", status.last_error},
      {"error_code", status.error_code},
    });
#else
    send_response(response, nlohmann::json {
      {"success", true},
      {"configured_backend", "disabled"},
      {"active_backend", ""},
      {"state", "unsupported"},
      {"component_available", false},
    });
#endif
  }

#ifdef _WIN32
  void
  getVddStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    const auto status = display_device::vdd_utils::get_vdd_status();
    send_response(response, nlohmann::json {
      {"status", true},
      {"state", status.state},
      {"installed", status.installed},
      {"running", status.running},
      {"control_available", status.control_available},
      {"monitor_active", status.monitor_active},
      {"problem_code_valid", status.problem_code_valid},
      {"problem_code", status.problem_code},
      {"version_supported", false},
    });
  }

  /**
   * @brief Deployment helper for our own Wintab32.dll.
   *
   * Windows resolves Wintab32.dll from the application directory before
   * System32, so dropping our build next to a drawing app's exe makes that one
   * app use it while everything else keeps whatever Wintab driver is installed.
   * That makes "install" a plain file copy and "uninstall" a delete -- no
   * driver store, no reboot, nothing global.
   */
  namespace wintab_deploy {
    // Apps that read WinTab and therefore can benefit. Matched against the
    // DisplayName of registered uninstall entries, then confirmed by looking
    // for the exe under InstallLocation.
    struct target_t {
      const char *name;
      const char *exe;
      const char *match;
    };

    constexpr target_t kTargets[] = {
      { "Clip Studio Paint", "CLIPStudioPaint.exe", "clip studio" },
      { "Krita", "krita.exe", "krita" },
      { "Adobe Photoshop", "Photoshop.exe", "photoshop" },
      { "Paint Tool SAI", "sai.exe", "paint tool sai" },
      { "FireAlpaca", "FireAlpaca.exe", "firealpaca" },
      { "MediBang Paint", "MediBangPaint.exe", "medibang" },
      { "OpenCanvas", "OpenCanvas.exe", "opencanvas" },
      { "Blender", "blender.exe", "blender" },
    };

    constexpr auto kDllName = "Wintab32.dll";

    std::filesystem::path
    bundled_dll_path() {
      // SUNSHINE_ASSETS_DIR is <root>/assets, so this is <root>/tools/wintab/.
      return file_handler::path_from_utf8(SUNSHINE_ASSETS_DIR).parent_path() / "tools" / "wintab" / kDllName;
    }

    // Cheap rolling hash; enough to tell "our build" from "some other Wintab32".
    std::uint64_t
    hash_file(const std::filesystem::path &path) {
      std::ifstream in(path, std::ios::binary);
      if (!in) return 0;

      std::uint64_t h = 1469598103934665603ull;
      char buf[65536];
      while (in.read(buf, sizeof(buf)) || in.gcount()) {
        for (std::streamsize i = 0; i < in.gcount(); ++i) {
          h ^= (unsigned char) buf[i];
          h *= 1099511628211ull;
        }
      }
      return h;
    }

    bool
    process_running(const std::string &exe_name) {
      HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if (snap == INVALID_HANDLE_VALUE) return false;

      PROCESSENTRY32W pe {};
      pe.dwSize = sizeof(pe);
      bool found = false;
      if (Process32FirstW(snap, &pe)) {
        do {
          std::wstring wide(pe.szExeFile);
          std::string narrow(wide.begin(), wide.end());
          if (!_stricmp(narrow.c_str(), exe_name.c_str())) {
            found = true;
            break;
          }
        } while (Process32NextW(snap, &pe));
      }
      CloseHandle(snap);
      return found;
    }

    bool
    dir_writable(const std::filesystem::path &dir) {
      std::error_code ec;
      if (!std::filesystem::is_directory(dir, ec)) return false;

      const auto probe = dir / ".superwintab_probe.tmp";
      {
        std::ofstream out(probe, std::ios::binary);
        if (!out) return false;
        out << "x";
      }
      std::filesystem::remove(probe, ec);
      return true;
    }

    // Search a few levels down from an install location for the app's exe.
    std::filesystem::path
    find_exe_dir(const std::filesystem::path &root, const std::string &exe) {
      std::error_code ec;
      if (root.empty() || !std::filesystem::is_directory(root, ec)) return {};

      constexpr int kMaxDepth = 3;
      for (std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, ec), end;
           it != end; it.increment(ec)) {
        if (ec) break;
        if (it->is_directory(ec) && it.depth() >= kMaxDepth) {
          it.disable_recursion_pending();
          continue;
        }
        if (!it->is_regular_file(ec)) continue;
        if (_stricmp(it->path().filename().string().c_str(), exe.c_str())) continue;
        return it->path().parent_path();
      }
      return {};
    }

    std::vector<std::string>
    uninstall_hive_paths() {
      return {
        R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall)",
        R"(SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall)",
      };
    }

    std::vector<std::pair<std::string, std::string>>
    installed_app_locations() {
      std::vector<std::pair<std::string, std::string>> out;  // {display name, install location}

      for (const auto &hive : uninstall_hive_paths()) {
        HKEY root_key = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hive.c_str(), 0, KEY_READ, &root_key) != ERROR_SUCCESS) continue;

        for (DWORD i = 0;; ++i) {
          char name[512];
          DWORD name_len = sizeof(name);
          if (RegEnumKeyExA(root_key, i, name, &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

          HKEY key = nullptr;
          if (RegOpenKeyExA(root_key, name, 0, KEY_READ, &key) != ERROR_SUCCESS) continue;

          char display[512] {};
          DWORD size = sizeof(display);
          DWORD type = 0;
          bool have_display = RegQueryValueExA(key, "DisplayName", nullptr, &type, (LPBYTE) display, &size) == ERROR_SUCCESS;

          char location[1024] {};
          size = sizeof(location);
          bool have_location = RegQueryValueExA(key, "InstallLocation", nullptr, &type, (LPBYTE) location, &size) == ERROR_SUCCESS;

          RegCloseKey(key);

          if (have_display && have_location && location[0]) {
            out.emplace_back(display, location);
          }
        }
        RegCloseKey(root_key);
      }
      return out;
    }

    nlohmann::json
    describe(const std::filesystem::path &dir, const std::string &name, const std::string &exe) {
      std::error_code ec;
      const auto dll = dir / kDllName;
      const bool installed = std::filesystem::exists(dll, ec);
      const auto bundled = bundled_dll_path();
      const bool bundled_present = std::filesystem::exists(bundled, ec);

      std::uint64_t dll_hash = installed ? hash_file(dll) : 0;
      std::uint64_t bundled_hash = bundled_present ? hash_file(bundled) : 0;

      return nlohmann::json {
        { "name", name },
        { "dir", file_handler::path_to_utf8(dir) },
        { "exe", exe },
        { "found", true },
        { "installed", installed },
        { "match", installed && bundled_present && dll_hash != 0 && dll_hash == bundled_hash },
        { "writable", dir_writable(dir) },
        { "running", process_running(exe) },
      };
    }

    std::vector<nlohmann::json>
    discover() {
      const auto apps = installed_app_locations();
      std::vector<nlohmann::json> out;

      for (const auto &target : kTargets) {
        for (const auto &[display, location] : apps) {
          std::string lower;
          lower.reserve(display.size());
          for (char c : display) lower.push_back((char) std::tolower((unsigned char) c));
          if (lower.find(target.match) == std::string::npos) continue;

          const auto dir = find_exe_dir(std::filesystem::path(location), target.exe);
          if (dir.empty()) continue;

          out.push_back(describe(dir, target.name, target.exe));
          break;
        }
      }
      return out;
    }

    // Copy the bundled DLL next to an app's exe. Returns false when the target is
    // missing, not a directory, or locked by a running instance.
    bool
    install_into(const std::filesystem::path &dir, std::string *error = nullptr) {
      std::error_code ec;
      const auto bundled = bundled_dll_path();
      if (!std::filesystem::exists(bundled, ec)) {
        if (error) *error = "缺少内置的 Wintab32.dll";
        return false;
      }
      if (!std::filesystem::is_directory(dir, ec)) {
        if (error) *error = "不是目录: " + file_handler::path_to_utf8(dir);
        return false;
      }

      const auto target = dir / kDllName;
      if (std::filesystem::exists(target, ec)) {
        // A running app holds the DLL open; overwriting fails with a sharing
        // violation, so remove first and report that plainly.
        std::filesystem::remove(target, ec);
        if (ec) {
          if (error) *error = "目标程序可能正在运行并锁定了 DLL";
          return false;
        }
      }

      std::filesystem::copy_file(bundled, target, std::filesystem::copy_options::overwrite_existing, ec);
      if (ec) {
        if (error) *error = ec.message();
        return false;
      }
      return true;
    }
  }  // namespace wintab_deploy

  void
  getWintabStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace wintab_deploy;

    std::error_code ec;
    const auto bundled = bundled_dll_path();
    const bool bundled_present = std::filesystem::exists(bundled, ec);

    send_response(response, nlohmann::json {
      { "status", true },
      { "bundled", bundled_present },
      // weakly_canonical so the UI shows a real path: SUNSHINE_ASSETS_DIR is a
      // relative "assets", which on its own tells the user nothing.
      { "bundled_path", file_handler::path_to_utf8(fs::weakly_canonical(bundled)) },
      { "targets", discover() },
    });
  }

  void
  installWintab(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace wintab_deploy;

    std::string dir;
    try {
      auto tree = nlohmann::json::parse(request->content.string());
      dir = tree.value("dir", std::string {});
    }
    catch (const std::exception &) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "Invalid request body" } });
      return;
    }

    if (dir.empty()) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "No target directory given" } });
      return;
    }

    std::error_code ec;
    const auto bundled = bundled_dll_path();
    if (!std::filesystem::exists(bundled, ec)) {
      send_response(response, nlohmann::json {
        { "status", false },
        { "message", "Bundled Wintab32.dll is missing from " + file_handler::path_to_utf8(fs::weakly_canonical(bundled)) },
      });
      return;
    }

    const std::filesystem::path target_dir(dir);
    if (!std::filesystem::is_directory(target_dir, ec)) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "Not a directory: " + dir } });
      return;
    }

    const auto target = target_dir / kDllName;
    if (std::filesystem::exists(target, ec)) {
      // A running app holds the DLL open; overwriting it fails with a sharing
      // violation. Say so plainly instead of surfacing a raw error code.
      std::filesystem::remove(target, ec);
      if (ec) {
        send_response(response, nlohmann::json {
          { "status", false },
          { "message", "无法替换现有的 Wintab32.dll —— 目标程序可能正在运行并锁定了它，请先关闭该程序再重试。" },
        });
        return;
      }
    }

    std::filesystem::copy_file(bundled, target, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      send_response(response, nlohmann::json {
        { "status", false },
        { "message", "Copy failed: " + ec.message() },
      });
      return;
    }

    BOOST_LOG(info) << "SuperSun: installed Wintab32.dll into "sv << dir;
    send_response(response, nlohmann::json { { "status", true }, { "message", "已安装，重启该绘图程序后生效。" } });
  }

  void
  uninstallWintab(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace wintab_deploy;

    std::string dir;
    try {
      auto tree = nlohmann::json::parse(request->content.string());
      dir = tree.value("dir", std::string {});
    }
    catch (const std::exception &) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "Invalid request body" } });
      return;
    }

    std::error_code ec;
    const auto target = std::filesystem::path(dir) / kDllName;
    if (!std::filesystem::exists(target, ec)) {
      send_response(response, nlohmann::json { { "status", true }, { "message", "本来就没有安装。" } });
      return;
    }

    std::filesystem::remove(target, ec);
    if (ec) {
      send_response(response, nlohmann::json {
        { "status", false },
        { "message", "无法删除 —— 目标程序可能正在运行，请先关闭它。" },
      });
      return;
    }

    BOOST_LOG(info) << "SuperSun: removed Wintab32.dll from "sv << dir;
    send_response(response, nlohmann::json { { "status", true }, { "message", "已卸载。" } });
  }

  // ---------------------------------------------------------------------------
  // 绘画模式 (Drawing Mode) preset
  //
  // "让以上功能全开" in one click: every S Pen channel enabled, the pen tuning
  // keys that used to be env-var-only, HEVC 4:4:4 with a high bitrate ceiling,
  // AV1 off (Snapdragon 865+ has no AV1 decoder), the tablet kept as an extended
  // display, and a 16:10 4K mode added to the virtual display's mode list.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // USB tether link detection + high-bandwidth switch.
  //
  // Sunshine itself never cared how the packets travel: it binds 0.0.0.0, so any
  // IP link works, including the USB RNDIS/NCM link Android exposes after USB
  // tethering. What used to cap throughput lives mostly on the *client* side:
  // moonlight-common-c clamps maximumBitrateKbps to 100 Mbps "because GFE", and
  // the settings slider stopped at 150 Mbps. Neither number means anything on a
  // wired link that measures ~1 Gbit/s at ~2 ms with no measurable loss.
  //
  // This namespace does the two things the host can actually do about it: tell
  // the operator whether such a link exists right now, and lift the host-side
  // ceilings (max_bitrate / fec_percentage) to match it.
  // ---------------------------------------------------------------------------
  namespace usb_link {
    // Wi-Fi-ish fallback: what drawing mode writes for a normal LAN/WLAN stream.
    constexpr int kWifiMaxBitrateKbps = 150000;
    constexpr int kWifiFecPercentage = 20;
    // USB: forward error correction is insurance against packet loss, and a wired
    // tether has none. 20% redundancy would be 20% of the pipe spent on nothing.
    constexpr int kUsbFecPercentage = 5;
    // Hard ceiling accepted elsewhere in Sunshine (stream.cpp rejects above it).
    constexpr int kAbsoluteMaxBitrateKbps = 800000;

    // Windows does not flag "this adapter is a phone tether", and friendly names
    // get localised ("以太网 2"), so match both name and driver description.
    constexpr std::string_view kTetherHints[] = {
      "remote ndis"sv, "rndis"sv, "ncm"sv, "android"sv,
      "usb ethernet"sv, "ethernet over usb"sv, "tether"sv, "adb"sv,
    };

    // Beware a 10/100 Mbit pseudo-adapter being promoted to "USB link".
    constexpr std::uint64_t kMinLinkSpeedBps = 100ULL * 1000ULL * 1000ULL;

    // Bitrate presets for a USB tether, in Kbps.
    //
    // These are deliberately *not* derived from the adapter's reported link
    // speed. A USB RNDIS adapter reports a nominal figure baked into the driver
    // (almost always exactly 1 Gbit/s) that has nothing to do with what the USB
    // link actually negotiated: put a USB 2.0 cable in and Windows still says
    // 1 Gbit/s while real TCP throughput collapses to ~300 Mbps. Deriving a
    // 70%-of-1-Gbit recommendation from that number would hand out 700 Mbps to
    // someone on a 300 Mbps link, which stutters far worse than the 150 Mbps
    // default it replaced.
    //
    // Measured on the target hardware (Galaxy Tab S7+ SM-T970, whose USB-C port
    // is USB 3.2 Gen 1 / 5 Gbit/s -- not USB 2.0): ~991 Mbit/s TCP, ~2 ms, zero
    // loss. So the aggressive preset still leaves headroom here, but it is the
    // user's call, not something we infer from a meaningless number.
    constexpr int kUsbConservativeKbps = 200000;
    constexpr int kUsbBalancedKbps = 400000;
    constexpr int kUsbAggressiveKbps = kAbsoluteMaxBitrateKbps;  // 800 Mbps, the ceiling stream.cpp accepts

    struct link_info {
      bool present = false;
      std::string adapter;
      std::string description;
      std::string ip;
      std::uint64_t speed_bps = 0;
      /// False for RNDIS: the reported speed is a driver constant, not a measurement.
      bool speed_reliable = true;
      std::string hint;
    };

#ifdef _WIN32
    std::string
    utf8_from_wide(const WCHAR *wide) {
      if (!wide) return {};
      const int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
      if (len <= 1) return {};
      std::string out((std::size_t) (len - 1), '\0');
      WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), len, nullptr, nullptr);
      return out;
    }

    std::string
    lower(std::string value) {
      for (auto &c : value) c = (char) std::tolower((unsigned char) c);
      return value;
    }

    bool
    looks_like_tether(const std::string &text) {
      const auto haystack = lower(text);
      if (haystack.empty()) return false;
      for (const auto hint : kTetherHints) {
        if (haystack.find(hint) != std::string::npos) return true;
      }
      return false;
    }

    // RNDIS is the classic Android tether protocol, and it is precisely the one
    // whose reported link speed is a hardcoded 1 Gbit/s rather than a measurement.
    bool
    looks_like_rndis(const std::string &text) {
      const auto haystack = lower(text);
      return haystack.find("rndis") != std::string::npos ||
             haystack.find("remote ndis") != std::string::npos;
    }

    // Link speeds are not part of IP_ADAPTER_ADDRESSES; they live in MIB_IF_TABLE2
    // keyed by the same IfIndex.
    std::uint64_t
    link_speed_for(NET_IFINDEX if_index) {
      PMIB_IF_TABLE2 table = nullptr;
      if (GetIfTable2(&table) != NO_ERROR || table == nullptr) return 0;

      std::uint64_t speed = 0;
      for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto &row = table->Table[i];
        if (row.InterfaceIndex != if_index) continue;
        speed = std::max<std::uint64_t>(row.ReceiveLinkSpeed, row.TransmitLinkSpeed);
        break;
      }

      FreeMibTable(table);
      return speed;
    }

    link_info
    detect() {
      link_info info;

      ULONG length = 15000;
      std::vector<std::uint8_t> buffer(length);
      auto addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

      if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, addresses, &length) != NO_ERROR) {
        info.hint = "枚举网卡失败（GetAdaptersAddresses）";
        return info;
      }

      std::uint64_t slowest_seen = 0;

      for (auto adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        if (adapter->IfType == IF_TYPE_TUNNEL || adapter->IfType == IF_TYPE_PPP) continue;

        const auto description = utf8_from_wide(adapter->Description);
        const auto friendly = utf8_from_wide(adapter->FriendlyName);
        if (!looks_like_tether(description) && !looks_like_tether(friendly)) continue;

        const auto speed = link_speed_for(adapter->IfIndex);
        if (speed < kMinLinkSpeedBps) {
          slowest_seen = speed;
          continue;
        }

        std::string ip;
        for (auto unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
          if (unicast->Address.lpSockaddr->sa_family != AF_INET) continue;
          auto sin = reinterpret_cast<sockaddr_in *>(unicast->Address.lpSockaddr);
          // 169.254/16 is the APIPA address every tethered interface also gets.
          if ((ntohl(sin->sin_addr.s_addr) >> 16) == 0xA9FE) continue;
          ip = boost::asio::ip::address_v4(ntohl(sin->sin_addr.s_addr)).to_string();
          break;
        }
        if (ip.empty()) continue;

        // A tablet often registers several plausible entries; keep the fastest.
        if (speed <= info.speed_bps) continue;

        info.present = true;
        info.adapter = friendly.empty() ? description : friendly;
        info.description = description;
        info.ip = ip;
        info.speed_bps = speed;
        // Any USB tether is a virtual NIC, so this is whatever the gadget driver
        // claims -- typically a fixed 1 Gbit/s -- and never a measurement. RNDIS
        // is the worst offender and gets an extra nudge towards NCM below.
        info.speed_reliable = false;
      }

      if (!info.present && info.hint.empty()) {
        info.hint = slowest_seen > 0
                      ? "找到 USB 网卡但它还没协商到可用速率（" + std::to_string(slowest_seen / 1000000) + " Mbps）。"
                      : "没有检测到已连接的 USB 网卡。请先用 adb 打开 USB 网络共享。";
      }

      // NCM is not a free win, so do not sell it as one. It batches many Ethernet
      // frames into one USB transfer, which is unambiguously cheaper on CPU and
      // wins on bulk throughput -- but the batching waits to fill a transfer, and
      // in a latency-sensitive small-packet workload (pen input, cursor moves)
      // that wait can cost more than it saves. USB NCM support on Windows is also
      // patchier than RNDIS, which every Windows since XP has handled natively.
      // Mention it as an experiment to measure, not an upgrade to apply.
      if (info.present && info.hint.empty() && looks_like_rndis(info.description)) {
        info.hint = "当前是 RNDIS。NCM 靠帧聚合能明显省 CPU、高负载吞吐更好，"
                    "但聚合等待对小包延迟未必有利，且 Windows 对 USB NCM 的支持不如 RNDIS 稳。"
                    "要试：adb shell svc usb setFunctions ncm,adb（Android 11+），"
                    "切完实测吞吐和 ping 再决定，别直接当升级。";
      }
      return info;
    }

    // Windows classifies every newly seen adapter as an unidentified network,
    // which means "public profile" -- and inbound Sunshine ports get dropped.
    // usb_link.py used to print these commands for the user to paste; since
    // Sunshine already runs elevated (ZakoVDD needs it) we can just run them.
    //
    // Only ever touches rules named kFirewallRule*, so removing is reversible and
    // nothing else in the user's firewall policy is disturbed.
    constexpr char kFirewallRuleTcp[] = "Sunshine USB (TCP)";
    constexpr char kFirewallRuleUdp[] = "Sunshine USB (UDP)";

    std::string
    quote(const std::string &value) {
      return "\"" + value + "\"";
    }

    std::string
    port_list(const std::vector<int> &offsets) {
      // Offsets are relative to the configured base port, see net::map_port().
      std::string out;
      for (auto offset : offsets) {
        if (!out.empty()) out += ",";
        out += std::to_string(net::map_port(offset));
      }
      return out;
    }

    int
    run_netsh(const std::string &arguments, std::string *output) {
      boost::filesystem::path working_dir;
      static const boost::process::v1::environment env = boost::this_process::environment();
      std::error_code ec;

      auto child = platf::run_command(false, false, "netsh " + arguments, working_dir, env, nullptr, ec, nullptr);
      if (ec) {
        if (output) *output = ec.message();
        return -1;
      }

      if (child.running()) child.wait();
      return child.exit_code();
    }

    bool
    ensure_firewall_rules(bool enable, std::string *error, std::vector<std::string> &changed) {
      const std::vector<int> tcp_ports {
        nvhttp::PORT_HTTP,
        nvhttp::PORT_HTTPS,
        confighttp::PORT_HTTPS,
        rtsp_stream::RTSP_SETUP_PORT,
      };
      const std::vector<int> udp_ports {
        stream::VIDEO_STREAM_PORT,
        stream::CONTROL_PORT,
        stream::AUDIO_STREAM_PORT,
        stream::MIC_STREAM_PORT,
      };

      // mDNS. This is the reason "unplug and it can't find the PC": the tether
      // adapter lands on the public profile, so without 5353 the tablet's
      // discovery query never arrives and discovery looks simply broken -- you
      // end up having to type the IP by hand. It is a fixed port, not an offset
      // from our base port, so it is appended rather than run through map_port.
      constexpr int kMdnsPort = 5353;

      for (const auto pass : { 0, 1 }) {
        const bool tcp = pass == 0;
        const auto &rule_name = tcp ? kFirewallRuleTcp : kFirewallRuleUdp;
        const auto ports = tcp ? port_list(tcp_ports)
                               : port_list(udp_ports) + "," + std::to_string(kMdnsPort);

        std::string ignored;
        const auto show = std::string { "advfirewall firewall show rule name=" } + quote(rule_name);
        const int exists = run_netsh(show, &ignored);

        if (enable) {
          // Delete first, do not skip when a rule already exists. An existing rule
          // can predate the current port list -- that is exactly what happened with
          // the mDNS port, which was added after the rule had been created: the
          // rule was "already there" and silently kept blocking 5353. Recreating is
          // idempotent and keeps the port list honest.
          run_netsh(std::string { "advfirewall firewall delete rule name=" } + quote(rule_name), &ignored);
          const auto add = std::string { "advfirewall firewall add rule name=" } + quote(rule_name) +
                           " dir=in action=allow profile=any" +
                           " protocol=" + (tcp ? "TCP" : "UDP") +
                           " localport=" + ports;
          std::string message;
          if (run_netsh(add, &message) != 0) {
            if (error) *error = "添加防火墙规则失败（Sunshine 需要以管理员运行）：" + message;
            return false;
          }
          changed.push_back((tcp ? "防火墙入站 TCP " : "防火墙入站 UDP ") + ports + " 已放行");
        }
        else {
          if (exists != 0) continue;  // 本来就没有
          const auto del = std::string { "advfirewall firewall delete rule name=" } + quote(rule_name);
          std::string message;
          if (run_netsh(del, &message) != 0) {
            if (error) *error = "删除防火墙规则失败：" + message;
            return false;
          }
          changed.push_back((tcp ? "防火墙入站 TCP " : "防火墙入站 UDP ") + ports + " 已还原");
        }
      }

      BOOST_LOG(info) << "SuperSun: USB firewall rules "sv
                      << (enable ? "added"sv : "removed"sv)
                      << " (base port "sv << config::sunshine.port << ")";
      return true;
    }
#else
    link_info
    detect() {
      link_info info;
      info.hint = "USB 链路检测目前只实现了 Windows 版本。";
      return info;
    }

    // Non-Windows stub: mirrors the Windows function used in applyUsbLink().
    bool
    ensure_firewall_rules(bool enable, std::string *error, std::vector<std::string> &changed) {
      (void) enable;
      (void) changed;
      if (error) *error = "防火墙放行目前只实现了 Windows 版本。";
      return false;
    }
#endif

    // Deliberately a preset, not a fraction of the reported speed -- see the
    // comment on kUsbBalancedKbps. Balanced is the default: comfortably inside
    // the ~991 Mbit/s this hardware actually sustains, and still sane if the
    // user swapped in a USB 2.0 cable (which would cap TCP at ~300 Mbps).
    int
    recommended_bitrate_kbps(const link_info &info) {
      if (!info.present) return kWifiMaxBitrateKbps;
      return kUsbBalancedKbps;
    }

    void
    build_bandwidth_patch(std::map<std::string, std::string> &patch, bool enable, int usb_bitrate_kbps) {
      if (enable) {
        patch["max_bitrate"] = std::to_string(usb_bitrate_kbps);
        patch["fec_percentage"] = std::to_string(kUsbFecPercentage);
      }
      else {
        patch["max_bitrate"] = std::to_string(kWifiMaxBitrateKbps);
        patch["fec_percentage"] = std::to_string(kWifiFecPercentage);
      }
    }

    // --- switching the tethering protocol between RNDIS and NCM ----------
    //
    // Offered because NCM is measurably cheaper on CPU, not because it is an
    // upgrade: see the comparison table in docs/USB直连与码率天花板.md. Switching
    // re-enumerates the USB device, so the link drops and the static IPs have to
    // be laid down again afterwards (usb_link.py up --mode <mode> does that).

    std::string
    find_adb() {
      const auto snapshot = config::get_config_snapshot();
      if (snapshot) {
        const auto it = snapshot->find("usb_adb_path");
        if (it != snapshot->end() && !it->second.empty() && fs::exists(it->second)) {
          return it->second;
        }
      }

      for (const auto candidate : { "E:/DshProject/platform-tools/adb.exe" }) {
        if (fs::exists(candidate)) return candidate;
      }

#ifdef _WIN32
      // anything on PATH
      wchar_t buffer[MAX_PATH];
      const auto length = SearchPathW(nullptr, L"adb.exe", nullptr, MAX_PATH, buffer, nullptr);
      if (length > 0 && length < MAX_PATH) {
        const std::wstring wide(buffer, (std::size_t) length);
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (bytes > 1) {
          std::string out((std::size_t) (bytes - 1), '\0');
          WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), bytes, nullptr, nullptr);
          return out;
        }
      }
#endif
      return {};
    }

    int
    run_capture(const std::string &cmd, std::string &out) {
#ifdef _WIN32
      FILE *pipe = _popen(cmd.c_str(), "r");
#else
      FILE *pipe = popen(cmd.c_str(), "r");
#endif
      if (!pipe) return -1;
      char buffer[1024];
      while (fgets(buffer, sizeof(buffer), pipe)) out += buffer;
#ifdef _WIN32
      return _pclose(pipe);
#else
      return pclose(pipe);
#endif
    }

    /// Which protocol the current tether is using, inferred from the adapter description.
    std::string
    mode_from_description(const std::string &description) {
      const auto haystack = [](std::string value) {
        for (auto &c : value) c = (char) std::tolower((unsigned char) c);
        return value;
      }(description);
      if (haystack.find("ncm") != std::string::npos) return "ncm";
      if (haystack.find("rndis") != std::string::npos) return "rndis";
      return "unknown";
    }

    struct switch_result {
      bool ok = false;
      std::string output;
      std::string detail;
    };

    switch_result
    switch_usb_mode(const std::string &mode) {
      switch_result result;

      if (mode != "rndis" && mode != "ncm") {
        result.detail = "只支持 rndis / ncm。";
        return result;
      }

      const auto adb = find_adb();
      if (adb.empty()) {
        result.detail = "没找到 adb.exe。在 sunshine.conf 里加一行 usb_adb_path = <完整路径> 再试。";
        return result;
      }

      const auto quoted = "\"" + adb + "\"";
      // `svc usb` needs root on the device, so escalate through su the same way
      // usb_link.py does. No shell quoting: adb joins its arguments with spaces
      // and the device shell mksh splits them back apart.
      const std::vector<std::string> attempts {
        quoted + " shell svc usb setFunctions " + mode + ",adb",
        quoted + " shell su -c svc usb setFunctions " + mode + ",adb",
        quoted + " shell su -c setprop sys.usb.config " + mode + ",adb",
      };

      for (const auto &cmd : attempts) {
        std::string out;
        const int rc = run_capture(cmd, out);
        result.output += "$ " + cmd + "\n" + out + "\n";
        if (rc == 0) {
          result.ok = true;
          return result;
        }
      }

      result.detail = "三条命令都失败了。常见原因：平板没给 shell root 授权，或 adb 设备不在线。";
      return result;
    }
  }  // namespace usb_link

  namespace drawing_mode {
    // ---------------------------------------------------------------------
    // Every setting this card can touch, described well enough that the user
    // can decide for themselves.
    //
    // The previous design applied a fixed preset in one shot. That was wrong in
    // two ways: the user could not see what was about to change, and the preset
    // overwrote choices they had made by hand (it kept turning nvenc_spatial_aq
    // back on after latency work had turned it off). So the preset is gone and
    // the UI now renders this list instead: each row states what the setting
    // does, shows the current value, and only writes the ones the user
    // actually changes.
    // ---------------------------------------------------------------------

    /// How the UI should render a row.
    enum class control_t {
      toggle,  ///< on/off
      choice,  ///< fixed set of string values
      number,  ///< numeric, with min/max
      text,    ///< free-form string
    };

    struct option_t {
      std::string key;
      control_t control;
      /// Grouping in the UI, so related settings sit together.
      const char *group;
      /// What the setting does, in the user's language.
      const char *label;
      const char *help;
      /// The value we suggest. Only ever used as the initial state of the
      /// editor -- it is written when the user saves, never on its own.
      std::string recommended;
      /// For control_t::choice
      std::vector<std::string> choices;
      /// Per-choice explanation, parallel to `choices`. Empty entries fall back
      /// to the raw value. A dropdown that just says "1 / 2 / 3 / autoselect"
      /// tells the reader nothing about what they are picking.
      std::vector<const char *> choice_notes;
      /// For control_t::number. Doubles, not integers: pen_pressure_gamma is a
      /// float (0.7 recommended) and validating it as an integer made the one
      /// setting people care most about impossible to save.
      double min = 0.0;
      double max = 0.0;
      /// Step the UI should offer. 0 means "derive it" (integers get 1).
      double step = 0.0;
    };

    const std::vector<option_t> &
    options() {
      using enum control_t;
      static const std::vector<option_t> opts {
        // The input channels (keyboard / mouse / controller / scancodes /
        // scrolling / native pen / touchpad / virtual mouse / cursor) and the
        // codec modes (hevc_mode / av1_mode) are deliberately NOT repeated here:
        // they already have editors on the Input and Advanced pages, and two
        // entries for one key is how this panel started contradicting itself.
        // Only settings with no other home belong in this list.
        //
        // max_bitrate is absent for the same reason -- the wired-link section
        // further down owns it and shows the live value.

        // --- 压感手感（全局设置里没有对应项） ---
        { "pen_pressure_gamma", number, "pen",
          "压感曲线",
          "小于 1.0 会把压力配额往轻压端挪，轻笔触不再全挤在最低的几级；"
          "1.0 是线性；大于 1.0 则重压更重。",
          // config.cpp accepts 0.0 < gamma <= 4.0, so the editor must not offer
          // anything outside that or the value would be silently dropped on
          // the next load.
          "0.7", {}, {}, 0.1, 4.0, 0.05 },
        { "pen_hover_pressure", number, "pen",
          "悬停压力",
          "笔悬在屏幕上时上报的压力值。保持 0 —— 一旦大于 0，画图软件会以为你已经落笔，"
          "然后在悬停时就开始画。",
          "0", {}, {}, 0, 64, 1 },

        // --- 编码器的画质 / 延迟取舍（高级页只给编码器与模式，不给这些） ---
        { "downscaling_quality", choice, "video",
          "缩放算法",
          "画面缩到平板分辨率时的插值方式。high_quality 最锐利，也最吃 CPU。",
          "high_quality", { "fast", "balanced", "high_quality" },
          { "最快，省 CPU，画面略软", "折中", "最锐利，最吃 CPU" }, 0, 0 },
        { "fixed_frame_cadence", toggle, "video",
          "帧率保活（静止时持续产生画面）",
          "开启后会在每块显示器左上角放一个 1x1 像素，按约 60Hz 在两档极接近的"
          "暗色之间切换，让桌面一直有变化。\n"
          "要解决的问题：编码循环是「等新画面再编码」，桌面完全静止时等不到新帧，"
          "这份等待白费、编码耗时再叠加上去，静止帧率会掉到 30~45fps，"
          "延迟在 6~9ms 之间来回摆（画几笔就停一下的话手感很受影响）。\n"
          "保活像素让采集层始终有新帧可发，帧率于是稳定在客户端请求值上。\n"
          "像素只有 1 个、颜色只差 1/255，基本看不出；代价是静止时也在编码，"
          "但画面几乎没变，压缩后极小。\n"
          "需要重启 Sunshine 后生效。",
          "enabled", {}, {}, 0, 0 },
        { "nvenc_spatial_aq", toggle, "video",
          "空间自适应量化",
          "把码率预算从平坦处挪到细节多的区域，同码率下更锐利。"
          "代价是一点编码时间；追求最低延迟可以关掉。",
          "disabled", {}, {}, 0, 0 },
        { "nvenc_lookahead_level", choice, "video",
          "NVENC 前瞻",
          "编码前先看后面几帧以提高压缩效率。autoselect 让驱动决定，disabled 最省延迟。",
          "disabled", { "disabled", "1", "2", "3", "autoselect" },
          { "关闭，最低延迟", "看1 帧，省一点码率", "看2 帧", "看3 帧，延迟最大",
            "由驱动按内容自动决定" }, 0, 0 },
        { "nvenc_temporal_filter", choice, "video",
          "NVENC 时域滤波",
          "跨帧去噪/去块。会引入延迟并糊掉细节，画精细线稿建议保持 disabled。",
          "disabled", { "disabled", "4" },
          { "关闭，画线稿应该保持这个", "强度4：去噪更强，但细节会被抹平" }, 0, 0 },

        // --- 虚拟屏：平板在主机上被当作什么显示器（AudioVideo 页只管分辨率列表） ---
        { "display_device_prep", choice, "display",
          "显示器拓扑",
          "ensure_secondary = 把虚拟屏作为扩展屏（物理屏保留）；"
          "ensure_only_display = 关掉物理屏只留虚拟屏；"
          "ensure_primary = 让虚拟屏成为主屏；no_operation = 不动。",
          "ensure_secondary",
          { "no_operation", "ensure_active", "ensure_primary", "ensure_only_display", "ensure_secondary" },
          { "完全不动", "激活已连接的虚拟屏", "虚拟屏变主屏", "关掉物理屏，只留虚拟屏",
            "虚拟屏作为扩展屏，物理屏保留" }, 0, 0 },
        { "output_name", text, "display",
          "虚拟屏适配器名",
          "要使用的虚拟显示器适配器。用默认的 Zako 虚拟屏就填 ZakoHDR。",
          "ZakoHDR", {}, {}, 0, 0 },

        // --- 主机桌面环境（不是串流参数，是对 Windows 桌面本身动手） ---
        { "drawing_fill_screen", toggle, "desktop",
          "铺满并锁定虚拟屏上的窗口",
          "绘图软件（CSP 等）最大化时只能贴到系统「工作区」，"
          "而工作区底部被任务栏占掉一条，画布下方总留一条空隙。\n"
          "勾选会把落在虚拟屏上的普通应用窗口拉大到整个屏幕，并**锁定**它："
          "拖不动、缩不了，直到你在这里取消勾选。适合开始画之前先勾上，避免误碰。\n"
          "取消勾选会完整还原窗口原来的大小、位置和边框。\n"
          "屏幕尺寸按当前虚拟屏分辨率自动识别，改分辨率后请重新勾选。"
          "主机屏幕上的窗口不受影响。立即生效，不需要重启 Sunshine。",
          "disabled", {}, {}, 0, 0 },

        // resolution_change and refresh_rate_change are deliberately absent:
        // both are already "automatic" in the config, so a control here would
        // only ever restate the current value. resolution_change stays
        // conditional on the client's "Optimize game settings" either way.
      };
      return opts;
    }

    // ---------------------------------------------------------------------
    // 把虚拟屏（副屏）上的应用窗口铺满整块屏。
    //
    // 为什么需要它：窗口「最大化」= 贴系统工作区( rcWork)，而工作区底部被
    // 任务栏占掉48px。实测 CSP 最大化后底部留 71px 空隙露出桌面壁纸。
    // explorer 的任务栏 auto-hide 也解决不了：ABM_SETSTATE(ABS_AUTOHIDE)
    // 在 Win10/11 上返回成功但状态不落（ABM_GETSTATE恒为 0），注册表
    // StuckRects3\TaskbarOn 等键在新版 explorer 里根本不存在。
    // 所以不去碰工作区，直接搬窗口 —— 用 MoveWindow 的语义而不是最大化。
    //
    // 屏幕尺寸**一律运行时读取**，绝不写死：虚拟屏分辨率由用户自己控制
    // （实测会在 1920x1200 / 2880x1800 等档位间切换），写死会当场失效。
    // ---------------------------------------------------------------------

    // 副屏（虚拟屏）的 rcMonitor。取不到返回 false。
    //
    // 用 Shell_SecondaryTrayWnd 定位而不是「非主屏」：将来若有第二块副屏，
    // 「非主屏」会把两块一起算进来。任务栏一定和它所在的屏同属一块。
    // 任务栏被 SW_HIDE 时 GetWindowRect 不准，所以走 MonitorFromWindow +GetMonitorInfo。
    bool
    secondary_monitor_rect(RECT &out) {
      const auto taskbar = FindWindowW(L"Shell_SecondaryTrayWnd", nullptr);
      if (taskbar == nullptr) {
        return false;
      }
      const auto mon = MonitorFromWindow(taskbar, MONITOR_DEFAULTTONEAREST);
      MONITORINFO mi {};
      mi.cbSize = sizeof(mi);
      if (GetMonitorInfoW(mon, &mi) == 0) {
        return false;
      }
      if ((mi.dwFlags & MONITORINFOF_PRIMARY) != 0) {
        return false;  // 万一没副屏任务栏，别把主屏交出去
      }
      out = mi.rcMonitor;
      return true;
    }

    // 搬运落在副屏上的普通应用窗口。返回搬运了几个。
    //
    // 窗口筛选判据（每条都经实测，别随意简化）：
    //   · 非 IsIconic                    —— 最小化的别动
    //   · 非 WS_EX_TOOLWINDOW            —— 排除托盘小窗/DesktopWindowXamlSource
    //   · 有 WS_CAPTION                   —— 排除 IME/通知等无边框窗口
    //   · 有窗口标题                      —— 排除桌面等无标题窗口
    //   · 尺寸 ≥ 屏幕 1/4                 —— 滤掉残余小窗
    //   · 窗口中心落在副屏                —— 判「属于这块屏」
    //   · 矩形已等于 rcMonitor            —— 已铺满则跳过，防抖动
    //
    // ★ 踩过的坑：曾用 GetWindow(hwnd, GW_OWNER) == nullptr 过滤普通窗口，
    //   结果一个都选不中 —— CSP（Chromium/Qt 系）的主窗口**本身就是 owned
    //   window 的 owner**，非 NULL，把该动的窗口全筛掉了。

    // ---------------------------------------------------------------------
    // 窗口锁定：防止用户误碰把铺满的窗口拖走 / 缩小。
    //
    // 做法就是改窗口样式，一次到位、不做后台轮询：
    //   勾选   —— 记下原始 style/exstyle，去掉 WS_THICKFRAME（鼠标拖不动边框、
    //             也拖不动标题栏以外的边），再把窗口铺满整块屏
    //   取消   —— 把记下的 style/exstyle 原样写回
    //
    // 为什么不加定时器把矩形按回去：应用窗口自己不会改大小，也没人会特意
    // 把它拖小；为了防一个不会发生的情况每200ms 醒一次不值得。
    // （实测过：清掉 WS_THICKFRAME 后用户确实拖不动，但程序侧 SetWindowPos
    //   仍能改矩形——那是Sunshine 自己的正常操作，不构成问题。）
    // ---------------------------------------------------------------------

    struct locked_window_t {
      HWND hwnd {};
      LONG_PTR style {};
      LONG_PTR ex_style {};
    };

    // 进程级单例：Web UI 是多线程的，锁定状态要跨线程共享。
    // 用 function-local static 而非全局变量，避免静态初始化顺序问题。
    class window_lock_t {
    public:
      // 锁定一批窗口。返回真正锁上的数量。
      int
      engage(const std::vector<HWND> &windows) {
        restore_styles();
        std::lock_guard<std::mutex> guard(mutex_);
        for (const HWND hwnd : windows) {
          if (!IsWindow(hwnd)) {
            continue;
          }
          locked_window_t entry {};
          entry.hwnd = hwnd;
          entry.style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
          entry.ex_style = ::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
          saved_.push_back(entry);
          // 去掉可缩放边框：用户没法拖边框改大小。
          ::SetWindowLongPtrW(hwnd, GWL_STYLE,
                              entry.style & ~static_cast<LONG_PTR>(WS_THICKFRAME));
        }
        active_ = !saved_.empty();
        return static_cast<int>(saved_.size());
      }

      // 还原被锁窗口的样式。幂等，没锁过就是空操作。
      // 不动几何：取消时把窗口缩回原样会打乱用户手动调过的布局，
      // 需要恢复大小自己双击标题栏最大化即可。
      int
      release_all() {
        std::lock_guard<std::mutex> guard(mutex_);
        const int n = static_cast<int>(saved_.size());
        for (const auto &entry : saved_) {
          if (!IsWindow(entry.hwnd)) {
            continue;  // 窗口已关，没什么可还原
          }
          ::SetWindowLongPtrW(entry.hwnd, GWL_STYLE, entry.style);
          ::SetWindowLongPtrW(entry.hwnd, GWL_EXSTYLE, entry.ex_style);
          // 边框样式变了，必须刷新非客户区，否则会残留旧边框的绘制。
          ::SetWindowPos(entry.hwnd, nullptr, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
        }
        saved_.clear();
        active_ = false;
        return n;
      }

      bool
      active() const {
        std::lock_guard<std::mutex> guard(mutex_);
        return active_;
      }

      // 进程级单例入口。
      static window_lock_t &
      instance() {
        static window_lock_t inst;
        return inst;
      }

    private:
      // 不加锁调用：只在 engage 内部、持锁之后使用。
      void
      restore_styles() {
        for (const auto &entry : saved_) {
          if (!IsWindow(entry.hwnd)) {
            continue;
          }
          ::SetWindowLongPtrW(entry.hwnd, GWL_STYLE, entry.style);
          ::SetWindowLongPtrW(entry.hwnd, GWL_EXSTYLE, entry.ex_style);
          ::SetWindowPos(entry.hwnd, nullptr, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
        }
        saved_.clear();
      }

      mutable std::mutex mutex_;  // mutable：active() 是 const 查询也要加锁
      std::vector<locked_window_t> saved_;
      bool active_ = false;
    };

    window_lock_t &
    window_lock() {
      return window_lock_t::instance();
    }

    // 铺满 + 锁定，合并成一个动作。返回被处理的窗口数。
    int
    fill_and_lock(bool lock) {
      RECT screen {};
      if (!secondary_monitor_rect(screen)) {
        BOOST_LOG(warning) << "SuperSun: no secondary monitor rect; skip fill";
        return 0;
      }

      if (lock && window_lock().active()) {
        return 0;  // 已经锁着，不重复搬
      }

      // 筛选逻辑与 fill_secondary_displays 相同：先把窗口铺满到屏幕，
      // 再把选中的窗口交给锁定器。
      // 再把它选中的窗口交给锁定器。分开实现会重复一遍筛选条件。
      std::vector<HWND> targets;
      const LONG screen_w = screen.right - screen.left;
      const LONG screen_h = screen.bottom - screen.top;
      const auto screen_center = MonitorFromPoint(
        POINT { screen.left + screen_w / 2, screen.top + screen_h / 2 },
        MONITOR_DEFAULTTONULL);

      struct Ctx {
        std::vector<HWND> *out;
        RECT screen;
        HMONITOR mon;
      } ctx { &targets, screen, screen_center };

      EnumWindows(
        [](HWND hwnd, LPARAM param) -> BOOL {
          auto *self = reinterpret_cast<Ctx *>(param);
          if (IsIconic(hwnd)) {
            return TRUE;
          }
          if ((::GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) != 0) {
            return TRUE;
          }
          if ((::GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_CAPTION) == 0) {
            return TRUE;
          }
          wchar_t title[256] {};
          if (GetWindowTextW(hwnd, title, ARRAYSIZE(title)) == 0) {
            return TRUE;
          }
          RECT r {};
          if (GetWindowRect(hwnd, &r) == 0) {
            return TRUE;
          }
          if (r.right - r.left < (self->screen.right - self->screen.left) / 4
              || r.bottom - r.top < (self->screen.bottom - self->screen.top) / 4) {
            return TRUE;
          }
          if (r.left == self->screen.left && r.top == self->screen.top
              && r.right == self->screen.right && r.bottom == self->screen.bottom) {
            return TRUE;
          }
          const POINT mid { (r.left + r.right) / 2, (r.top + r.bottom) / 2 };
          if (MonitorFromPoint(mid, MONITOR_DEFAULTTONULL) != self->mon) {
            return TRUE;
          }
          self->out->push_back(hwnd);
          return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));

      if (targets.empty()) {
        return 0;
      }

      for (const HWND hwnd : targets) {
        SetWindowPos(hwnd, nullptr, screen.left, screen.top, screen_w, screen_h,
                     SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
      }

      if (!lock) {
        return static_cast<int>(targets.size());
      }
      // 返回实际锁上的数量：窗口可能在这一步被别人关掉，
      // 让提示里的数字与真实状态一致。
      return window_lock().engage(targets);
    }

    const option_t *
    find_option(const std::string &key) {
      for (const auto &opt : options()) {
        if (opt.key == key) return &opt;
      }
      return nullptr;
    }

    /// The value we suggest for [key], or an empty optional when unknown.
    boost::optional<std::string>
    recommended_for(const std::string &key) {
      const auto *opt = find_option(key);
      if (opt == nullptr) return boost::none;
      return opt->recommended;
    }

    // There is no preset table: each option carries its own recommended value.
    // The virtual-display resolution list is not touched here at all -- the
    // user drives that from the client, and rewriting vdd_settings.xml behind
    // their back is what this card used to do (see the removed with_resolution
    // / patch_vdd_modes helpers).

    // config.cpp's to_bool() accepts "true"/"yes"/"enable"/"enabled"/"on"/"1"
    // alike, so `capture_cursor = true` already satisfies a target of
    // "enabled". Treat them as equal or the panel reports a永久 pending diff.
    std::string
    canonical_bool(const std::string &value) {
      std::string lower;
      lower.reserve(value.size());
      for (char c : value) lower.push_back((char) std::tolower((unsigned char) c));

      if (lower == "true" || lower == "yes" || lower == "enable" || lower == "enabled" || lower == "on" || lower == "1") return "enabled";
      if (lower == "false" || lower == "no" || lower == "disable" || lower == "disabled" || lower == "off" || lower == "0") return "disabled";
      return lower;
    }

    bool
    value_matches(const std::string &target, const std::string &current) {
      if (target == current) return true;
      if (target == "enabled" || target == "disabled") return canonical_bool(current) == target;
      return false;
    }

    // Rewrite only the `key = value` lines the preset touches, so every comment
    // in sunshine.conf survives. config::update_config() rebuilds the file from
    // the parsed map and would silently drop all of them.
    bool
    patch_conf(const std::map<std::string, std::string> &patch, std::vector<std::string> &changed) {
      const auto content = file_handler::read_file(config::sunshine.config_file.c_str());

      std::vector<std::string> lines;
      {
        std::istringstream in { content };
        std::string line;
        while (std::getline(in, line)) {
          if (!line.empty() && line.back() == '\r') line.pop_back();
          lines.push_back(line);
        }
      }

      static const boost::regex kv { "^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*?)\\s*$" };
      std::set<std::string> seen;

      for (auto &line : lines) {
        boost::smatch m;
        if (!boost::regex_match(line, m, kv)) continue;

        const std::string key = m[1].str();
        const auto it = patch.find(key);
        if (it == patch.end()) continue;

        seen.insert(key);
        const std::string before = m[2].str();
        if (value_matches(it->second, before)) continue;

        changed.push_back(key + ": " + before + " -> " + it->second);
        line = key + " = " + it->second;
      }

      for (const auto &[key, value] : patch) {
        if (seen.count(key)) continue;
        changed.push_back(key + ": (新增) -> " + value);
        lines.push_back(key + " = " + value);
      }

      if (changed.empty()) return true;

      std::string out;
      for (const auto &line : lines) out += line + "\n";
      return file_handler::write_file(config::sunshine.config_file.c_str(), out) == 0;
    }

    // No VDD patching on purpose. This used to splice a 3840x2400 mode into
    // ZakoVDD's <resolutions> behind the user's back, which fought with the
    // resolution list they edit in the client. The client owns that now.

    /// Validate one incoming value against the option's declared domain.
    /// A bad value is rejected rather than written, so a crafted request
    /// cannot push arbitrary strings into sunshine.conf.
    bool
    validate(const option_t &opt, const std::string &value, std::string &why) {
      switch (opt.control) {
        case control_t::toggle:
          if (canonical_bool(value) != "enabled" && canonical_bool(value) != "disabled") {
            why = "只能是 enabled / disabled";
            return false;
          }
          return true;
        case control_t::choice: {
          const auto canonical = value == "enabled" || value == "disabled" ? canonical_bool(value) : value;
          if (std::find(opt.choices.begin(), opt.choices.end(), canonical) == opt.choices.end()) {
            why = "可选值：" + boost::algorithm::join(opt.choices, " / ");
            return false;
          }
          return true;
        }
        case control_t::number: {
          // Double, not integer: pen_pressure_gamma is a float and stoll()
          // rejected every legal value for it ("0.7" -> "不是合法数字"),
          // which made the most-wanted setting unsaveable.
          try {
            size_t used = 0;
            const auto parsed = std::stod(value, &used);
            if (used != value.size() || !std::isfinite(parsed)) {
              why = "不是合法数字";
              return false;
            }
            if (parsed < opt.min || parsed > opt.max) {
              // Format without the trailing zeros std::to_string puts on doubles
              // ("0.100000" reads like a bug in a validation message).
              const auto trim = [](double v) {
                auto s = std::to_string(v);
                if (s.find('.') == std::string::npos) return s;
                while (!s.empty() && s.back() == '0') s.pop_back();
                if (!s.empty() && s.back() == '.') s.pop_back();
                return s;
              };
              why = "超出范围 " + trim(opt.min) + " ~ " + trim(opt.max);
              return false;
            }
          }
          catch (const std::exception &) {
            why = "不是合法数字";
            return false;
          }
          return true;
        }
        case control_t::text:
          if (value.empty() || value.size() > 64) {
            why = "不能为空且不超过 64 字符";
            return false;
          }
          return true;
      }
      why = "未知类型";
      return false;
    }

    /// Read a key out of the live config, or an empty string when unset.
    std::string
    current_value(const std::optional<std::map<std::string, std::string>> &snapshot, const std::string &key) {
      if (!snapshot) return {};
      const auto it = snapshot->find(key);
      return it == snapshot->end() ? std::string {} : it->second;
    }
  }  // namespace drawing_mode

  void
  getDrawingMode(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace drawing_mode;

    const auto snapshot = config::get_config_snapshot();

    // Hand the UI the full list with current values, so it can render an
    // editor. There is deliberately no "apply everything" any more: the user
    // picks the rows they want and only those get written.
    nlohmann::json items = nlohmann::json::array();
    for (const auto &opt : options()) {
      const auto current = current_value(snapshot, opt.key);

      const char *control = "toggle";
      switch (opt.control) {
        case control_t::toggle: control = "toggle"; break;
        case control_t::choice: control = "choice"; break;
        case control_t::number: control = "number"; break;
        case control_t::text: control = "text"; break;
      }

      nlohmann::json row {
        { "key", opt.key },
        { "control", control },
        { "group", opt.group },
        { "label", opt.label },
        { "help", opt.help },
        { "recommended", opt.recommended },
        { "value", current },
        { "is_default", current.empty() || value_matches(opt.recommended, current) },
      };
      if (opt.control == control_t::choice) {
        row["choices"] = opt.choices;
        // Parallel array; the UI pairs them by index and falls back to the raw
        // value for any empty note.
        nlohmann::json notes = nlohmann::json::array();
        for (const auto *note : opt.choice_notes) notes.push_back(note ? note : "");
        row["choice_notes"] = std::move(notes);
      }
      if (opt.control == control_t::number) {
        row["lo"] = opt.min;
        row["hi"] = opt.max;
        // Ship the step instead of hardcoding 1 in the UI: a step of 1 makes
        // the spinner jump straight past 0.7.
        row["step"] = opt.step > 0.0 ? opt.step : 1.0;
      }
      items.push_back(std::move(row));
    }

    send_response(response, nlohmann::json {
      { "status", true },
      { "items", items },
      { "restart_required", true },
    });
  }

  void
  applyDrawingMode(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace drawing_mode;

    // The request carries only the rows the user actually touched. Anything
    // absent is left exactly as it is -- that is the whole point of dropping
    // the preset.
    nlohmann::json body;
    try {
      body = nlohmann::json::parse(request->content.string());
    }
    catch (const std::exception &) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "请求格式不对。" } });
      return;
    }
    if (!body.is_object() || !body.contains("values") || !body["values"].is_object()) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "没有要写入的项。" } });
      return;
    }

    std::map<std::string, std::string> patch;
    nlohmann::json rejected = nlohmann::json::array();

    for (const auto &[key, raw] : body["values"].items()) {
      const auto *opt = find_option(key);
      if (opt == nullptr) {
        rejected.push_back({ { "key", key }, { "reason", "未知设置项" } });
        continue;
      }
      if (!raw.is_string()) {
        rejected.push_back({ { "key", key }, { "reason", "值必须是字符串" } });
        continue;
      }

      auto value = raw.get<std::string>();
      // Toggles are stored in the file as enabled/disabled, so normalise
      // whatever the client sent (true/false/on/1) into that spelling.
      if (opt->control == control_t::toggle) value = canonical_bool(value);

      std::string why;
      if (!validate(*opt, value, why)) {
        rejected.push_back({ { "key", key }, { "reason", why } });
        continue;
      }
      patch[key] = value;
    }

    if (!rejected.empty()) {
      send_response(response, nlohmann::json {
        { "status", false },
        { "rejected", rejected },
        { "message", "有几项没通过校验，什么都没写入。" },
      });
      return;
    }

    std::vector<std::string> changed;
    if (!patch.empty() && !patch_conf(patch, changed)) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "写入 sunshine.conf 失败。" } });
      return;
    }

    // drawing_fill_screen 是一件"现在就做"的事，不能混进"重启后生效"的提示里。
    // patch_conf 照样把状态写进 conf 供前端回显，这里只把它从 changed 里摘掉。
    const std::string fill_key { "drawing_fill_screen" };
    std::string immediate_note;
    if (const auto it = patch.find(fill_key); it != patch.end()) {
      if (it->second == "enabled") {
        const int n = fill_and_lock(true);
        immediate_note = n > 0 ? "已铺满虚拟屏并锁定 " + std::to_string(n) + " 个窗口。"
                               : (window_lock().active()
                                    ? "窗口已经锁定，无需重复操作。"
                                    : "虚拟屏上没找到可调整的窗口（软件可能没开在虚拟屏上）。");
      } else {
        const int n = window_lock().release_all();
        immediate_note = n > 0 ? "已解锁并还原 " + std::to_string(n) + " 个窗口的大小和位置。"
                               : "当前没有锁定的窗口。";
      }
      std::erase_if(changed, [&fill_key](const std::string &entry) {
        return entry.starts_with(fill_key);
      });
    }

    BOOST_LOG(info) << "SuperSun: drawing settings saved; "sv << changed.size() << " change(s)";
    if (!immediate_note.empty()) {
      BOOST_LOG(info) << "SuperSun: "sv << immediate_note;
    }

    std::string message;
    if (!immediate_note.empty()) {
      message = immediate_note;
      if (!changed.empty()) {
        message += " 另有 " + std::to_string(changed.size()) + " 项需要重启 Sunshine 后生效。";
      }
    } else {
      message = changed.empty() ? "没有改动。" : "已保存 " + std::to_string(changed.size()) + " 项，重启 Sunshine 后生效。";
    }

    send_response(response, nlohmann::json {
      { "status", true },
      { "changed", changed },
      { "restart_required", !changed.empty() },
      { "message", message },
    });
  }

  void
  getUsbLink(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace usb_link;

    const auto snapshot = config::get_config_snapshot();
    const auto read_int = [&snapshot](const char *key, int fallback) {
      if (!snapshot) return fallback;
      const auto it = snapshot->find(key);
      if (it == snapshot->end() || it->second.empty()) return fallback;
      try {
        return std::stoi(it->second);
      }
      catch (const std::exception &) {
        return fallback;
      }
    };

    const auto max_bitrate = read_int("max_bitrate", kWifiMaxBitrateKbps);
    const auto fec_percentage = read_int("fec_percentage", kWifiFecPercentage);

    const auto link = detect();
    const auto recommended = recommended_bitrate_kbps(link);

    send_response(response, nlohmann::json {
      { "status", true },
      { "supported", true },
      { "present", link.present },
      { "adapter", link.adapter },
      { "description", link.description },
      { "ip", link.ip },
      { "link_speed_mbps", link.speed_bps / 1000000ULL },
      // False for RNDIS: the number is whatever the driver feels like reporting,
      // so the UI must not present it as a measured throughput.
      { "speed_reliable", link.speed_reliable },
      { "recommended_bitrate", recommended },
      { "presets", nlohmann::json::array({
          { { "bitrate", kUsbConservativeKbps }, { "label", "conservative"sv } },
          { { "bitrate", kUsbBalancedKbps }, { "label", "balanced"sv } },
          { { "bitrate", kUsbAggressiveKbps }, { "label", "aggressive"sv } },
        }) },
      { "max_bitrate", max_bitrate },
      { "fec_percentage", fec_percentage },
      { "high_bandwidth", max_bitrate >= recommended && fec_percentage <= kUsbFecPercentage },
      { "mode", link.present ? mode_from_description(link.description) : "" },
      { "adb_found", !find_adb().empty() },
      { "hint", link.hint },
    });
  }

  void
  switchUsbMode(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace usb_link;

    std::string mode = "ncm";
    try {
      const auto body = nlohmann::json::parse(request->content.string());
      mode = body.value("mode", "ncm");
    }
    catch (const std::exception &) {
      // empty body defaults to ncm
    }

    const auto result = switch_usb_mode(mode);

    BOOST_LOG(info) << "SuperSun: USB tether switch to "sv << mode
                    << (result.ok ? " succeeded"sv : " failed"sv);

    send_response(response, nlohmann::json {
      { "status", result.ok },
      { "mode", mode },
      { "output", result.output },
      { "detail", result.detail },
      { "need_relink", result.ok },
      { "message", result.ok
          ? ("已把平板 USB 切成 " + mode + "。USB 会重新枚举，链路会断一下；"
             "重新配 IP 才能用：bash tools/usb_link/usb_link.py up --mode " + mode)
          : ("切换失败：" + result.detail) },
    });
  }

  void
  applyUsbLink(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    using namespace usb_link;

    bool enable = true;
    bool firewall = false;
    int requested_bitrate = 0;
    try {
      const auto body = nlohmann::json::parse(request->content.string());
      enable = body.value("enable", true);
      firewall = body.value("firewall", false);
      requested_bitrate = body.value("bitrate", 0);
    }
    catch (const std::exception &) {
      // 空 body 视为「开」
    }

    if (requested_bitrate <= 0) requested_bitrate = recommended_bitrate_kbps(detect());
    requested_bitrate = std::min(requested_bitrate, kAbsoluteMaxBitrateKbps);

    std::vector<std::string> changed;
    std::string firewall_error;

    if (firewall) {
      // Windows classifies a newly appeared adapter as an unidentified network,
      // i.e. "public" profile, and inbound Sunshine traffic gets dropped. Only
      // our own named rules are touched, so this is reversible from the UI.
      if (!ensure_firewall_rules(enable, &firewall_error, changed) && enable) {
        firewall_error = firewall_error.empty() ? "放行失败" : firewall_error;
      }
    }

    std::map<std::string, std::string> patch;
    build_bandwidth_patch(patch, enable, requested_bitrate);

    if (!drawing_mode::patch_conf(patch, changed)) {
      send_response(response, nlohmann::json { { "status", false }, { "message", "写入 sunshine.conf 失败。" } });
      return;
    }

    BOOST_LOG(info) << "SuperSun: USB high-bandwidth link "sv
                    << (enable ? "enabled"sv : "disabled"sv) << "; "sv
                    << changed.size() << " change(s)";

    send_response(response, nlohmann::json {
      { "status", true },
      { "enable", enable },
      { "changed", changed },
      { "firewall_applied", firewall },
      { "firewall_error", firewall_error },
      { "restart_required", true },
      { "message", changed.empty() ? "已经是目标状态，无需改动。" : "已写入配置，重启 Sunshine 后生效。" },
    });
  }

  void
  writeVulkanHdrBridgeStatus(resp_https_t response, bool operation_status) {
    const auto bridge_status = platf::vulkan_hdr_bridge::status();
    nlohmann::json output {
      {"status", operation_status},
      {"state", bridge_status.state},
      {"message", bridge_status.message},
      {"registered", bridge_status.registered},
      {"artifacts_installed", bridge_status.artifacts_installed},
      {"display_available", bridge_status.display_available},
    };
    send_response(std::move(response), output);
  }

  void
  getVulkanHdrBridgeStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    writeVulkanHdrBridgeStatus(response, true);
  }

  void
  validateVulkanHdrBridge(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    writeVulkanHdrBridgeStatus(response, platf::vulkan_hdr_bridge::validate_now());
  }
#endif

  void
  savePassword(resp_https_t response, req_https_t request) {
    if (!authorize_browser_request(response, request)) return;
    if (!check_content_type(response, request, "application/json")) return;
    if (!config::sunshine.username.empty() && !authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      pt::read_json(ss, inputTree);
      auto username = inputTree.count("currentUsername") > 0 ? inputTree.get<std::string>("currentUsername") : "";
      auto newUsername = inputTree.get<std::string>("newUsername");
      auto password = inputTree.count("currentPassword") > 0 ? inputTree.get<std::string>("currentPassword") : "";
      auto newPassword = inputTree.count("newPassword") > 0 ? inputTree.get<std::string>("newPassword") : "";
      auto confirmPassword = inputTree.count("confirmNewPassword") > 0 ? inputTree.get<std::string>("confirmNewPassword") : "";

      // Validate credential lengths
      if (newUsername.size() > 128) {
        outputTree.put("status", false);
        outputTree.put("error", "Username too long (max 128)");
        return;
      }
      if (newPassword.size() > 256) {
        outputTree.put("status", false);
        outputTree.put("error", "Password too long (max 256)");
        return;
      }

      if (newUsername.length() == 0) newUsername = username;
      if (newUsername.length() == 0) {
        outputTree.put("status", false);
        outputTree.put("error", "Invalid Username");
      }
      else {
        auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();
        if (config::sunshine.username.empty() || (boost::iequals(username, config::sunshine.username) && hash == config::sunshine.password)) {
          if (newPassword.empty() || newPassword != confirmPassword) {
            outputTree.put("status", false);
            outputTree.put("error", "Password Mismatch");
          }
          else {
            if (http::save_user_creds(config::sunshine.credentials_file, newUsername, newPassword) != 0 ||
                http::reload_user_creds(config::sunshine.credentials_file) != 0) {
              outputTree.put("status", false);
              outputTree.put("error", "Failed to save credentials");
            }
            else {
              outputTree.put("status", true);
            }
          }
        }
        else {
          outputTree.put("status", false);
          outputTree.put("error", "Invalid Current Credentials");
        }
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePassword: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  savePin(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      pt::read_json(ss, inputTree);
      std::string pin = inputTree.get<std::string>("pin");
      std::string name = inputTree.get<std::string>("name");

      // Validate PIN: must be numeric digits only, 4-8 characters
      if (pin.size() < 4 || pin.size() > 8 || !std::all_of(pin.begin(), pin.end(), ::isdigit)) {
        outputTree.put("status", false);
        outputTree.put("error", "PIN must be 4-8 digits");
        return;
      }
      // Validate client name
      if (name.empty() || name.size() > 256) {
        outputTree.put("status", false);
        outputTree.put("error", "Client name must be 1-256 characters");
        return;
      }

      bool pin_result = nvhttp::pin(pin, name);
      outputTree.put("status", pin_result);

      try {
        webhook::send_event_async(webhook::event_t{
          .type = pin_result ? webhook::event_type_t::CONFIG_PIN_SUCCESS : webhook::event_type_t::CONFIG_PIN_FAILED,
          .timestamp = webhook::get_current_timestamp(),
          .client_name = name,
          .client_ip = net::addr_to_normalized_string(request->remote_endpoint().address()),
          .server_ip = net::addr_to_normalized_string(request->local_endpoint().address())
        });
      }
      catch (...) {
        BOOST_LOG(error) << "Webhook pairing event construction failed"sv;
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePin: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());

      try {
        webhook::send_event_async(webhook::event_t{
          .type = webhook::event_type_t::CONFIG_PIN_FAILED,
          .timestamp = webhook::get_current_timestamp(),
          .client_ip = net::addr_to_normalized_string(request->remote_endpoint().address()),
          .server_ip = net::addr_to_normalized_string(request->local_endpoint().address()),
          .extra_data = {{"error", "invalid_request"}}
        });
      }
      catch (...) {
        BOOST_LOG(error) << "Webhook pairing failure event construction failed"sv;
      }
      return;
    }
  }

  void
  getQrPairStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    nlohmann::json j;
    j["status"] = nvhttp::get_qr_pair_status();

    std::string content = j.dump();
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(SimpleWeb::StatusCode::success_ok, content, headers);
  }

  void
  generateQrPairInfo(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    // Generate a random 4-digit PIN using OpenSSL CSPRNG
    const auto random_bytes = crypto::rand(sizeof(std::uint16_t));
    if (random_bytes.size() != sizeof(std::uint16_t)) {
      outputTree.put("status", false);
      outputTree.put("error", "Failed to generate pairing PIN");
      return;
    }
    std::uint16_t random_val;
    std::memcpy(&random_val, random_bytes.data(), sizeof(random_val));
    int pin_num = random_val % 10000;
    char pin_buf[5];
    std::snprintf(pin_buf, sizeof(pin_buf), "%04d", pin_num);
    std::string pin(pin_buf);

    // Set the preset PIN in nvhttp (valid for 120 seconds)
    std::string server_name = config::nvhttp.sunshine_name;
    if (!nvhttp::set_preset_pin(pin, server_name, 120)) {
      outputTree.put("status", false);
      outputTree.put("error", "Failed to set preset PIN");
      return;
    }

    // Get server address info
    auto local_addr = net::addr_to_normalized_string(request->local_endpoint().address());
    auto port = net::map_port(nvhttp::PORT_HTTP);

    // Determine the host address for the QR code URL
    std::string host;
    if (!config::nvhttp.external_ip.empty()) {
      // User explicitly configured an external IP (could be WAN for port-forwarded setups)
      host = config::nvhttp.external_ip;
    }
    else {
      // Detect a usable LAN IP (local_endpoint may be loopback or VPN)
      host = local_addr;
      auto host_net_type = net::from_address(host);
      if (host_net_type != net::LAN) {
        std::string resolved_host;

        // Method 1: UDP connect trick to find default outgoing interface
        try {
          boost::asio::io_context io_ctx;
          boost::asio::ip::udp::socket socket(io_ctx);
          socket.connect(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("8.8.8.8"), 53));
          auto lan_addr = socket.local_endpoint().address();
          socket.close();
          auto candidate = net::addr_to_normalized_string(lan_addr);
          if (net::from_address(candidate) == net::LAN) {
            resolved_host = candidate;
          }
        }
        catch (...) {}

#ifdef _WIN32
        // Method 2 (Windows): enumerate adapters via GetAdaptersAddresses
        if (resolved_host.empty()) {
          ULONG bufLen = 15000;
          std::vector<uint8_t> buf(bufLen);
          auto pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
          if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, pAddresses, &bufLen) == NO_ERROR) {
            for (auto adapter = pAddresses; adapter; adapter = adapter->Next) {
              if (adapter->OperStatus != IfOperStatusUp) continue;
              if (adapter->IfType == IF_TYPE_TUNNEL || adapter->IfType == IF_TYPE_PPP) continue;
              for (auto unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                if (unicast->Address.lpSockaddr->sa_family != AF_INET) continue;
                auto sin = reinterpret_cast<sockaddr_in *>(unicast->Address.lpSockaddr);
                boost::asio::ip::address_v4 addr(ntohl(sin->sin_addr.s_addr));
                auto candidate = addr.to_string();
                if (net::from_address(candidate) == net::LAN) {
                  resolved_host = candidate;
                  break;
                }
              }
              if (!resolved_host.empty()) break;
            }
          }
        }
#endif

        if (!resolved_host.empty()) {
          host = resolved_host;
          BOOST_LOG(info) << "QR pair: resolved to LAN IP " << host;
        }
        else {
          BOOST_LOG(warning) << "QR pair: could not find a LAN IP, using " << host;
        }
      }
    }

    // Build the moonlight:// URL
    std::string url = "moonlight://pair?host=" + host +
                      "&port=" + std::to_string(port) +
                      "&pin=" + pin +
                      "&name=" + server_name;

    outputTree.put("status", true);
    outputTree.put("pin", pin);
    outputTree.put("host", host);
    outputTree.put("port", port);
    outputTree.put("name", server_name);
    outputTree.put("url", url);
    outputTree.put("expires_in", 120);
  }

  void
  cancelQrPair(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    nvhttp::clear_preset_pin();

    pt::ptree outputTree;
    outputTree.put("status", true);

    std::ostringstream data;
    pt::write_json(data, outputTree);
    response->write(data.str());
  }

  void
  unpairAll(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });
    nvhttp::erase_all_clients();
    proc::proc.terminate();
    outputTree.put("status", true);
  }

  void
  unpair(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      pt::read_json(ss, inputTree);
      std::string uuid = inputTree.get<std::string>("uuid");

      // Validate UUID format (hex + hyphens, reasonable length)
      if (uuid.empty() || uuid.size() > 64) {
        outputTree.put("status", false);
        outputTree.put("error", "Invalid client UUID");
        return;
      }

      const bool removed = nvhttp::unpair_client(uuid);
      outputTree.put("status", removed);

      if (removed && nvhttp::get_all_clients().empty()) {
        proc::proc.terminate();
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "Unpair: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  renameClient(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      std::stringstream ss;
      ss << request->content.rdbuf();
      pt::read_json(ss, inputTree);

      std::string uuid = inputTree.get<std::string>("uuid");
      std::string new_name = inputTree.get<std::string>("name");

      if (new_name.empty()) {
        outputTree.put("status", false);
        outputTree.put("error", "Name cannot be empty");
        return;
      }

      bool result = nvhttp::rename_client(uuid, new_name);
      outputTree.put("status", result);
      if (!result) {
        outputTree.put("error", "Client not found");
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "Rename client: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
    }
  }

  void
  listClients(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);
    nlohmann::json named_certs = nvhttp::get_all_clients();
    const auto sessions = stream::session::get_all_sessions_info();
    for (auto &client : named_certs) {
      if (!client.is_object()) continue;
      const auto uuid = client.value("uuid", std::string {});
      const auto name = client.value("name", std::string {});
      const auto session = std::find_if(sessions.begin(), sessions.end(), [&](const auto &candidate) {
        return (!uuid.empty() && candidate.client_uuid == uuid) ||
               (uuid.empty() && !name.empty() && candidate.client_name == name);
      });
      if (session == sessions.end()) continue;

      client["hdrBrightnessRuntime"] = {
        { "active", true },
        { "reported", session->hdr_brightness_reported },
        { "source", session->hdr_brightness_source },
        { "maxNits", session->hdr_max_nits },
        { "minNits", session->hdr_min_nits },
        { "maxFullFrameNits", session->hdr_max_full_frame_nits },
      };
    }
    nlohmann::json output_tree;
    output_tree["named_certs"] = named_certs;
    output_tree["status"] = "true";
    send_response(response, output_tree);
  }

  void
  listColorProfiles(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

#ifdef _WIN32
    const auto windows_directory = []() -> std::filesystem::path {
      if (const char *windir = std::getenv("WINDIR"); windir && *windir) {
        return windir;
      }
      return R"(C:\Windows)";
    }();
    const auto color_directory = windows_directory / "System32" / "spool" / "drivers" / "color";

    std::error_code error;
    std::vector<std::string> profiles;
    std::filesystem::directory_iterator entry { color_directory, std::filesystem::directory_options::skip_permission_denied, error };
    const std::filesystem::directory_iterator end;
    while (!error && entry != end) {
      std::error_code entry_error;
      if (entry->is_regular_file(entry_error) && !entry_error) {
        const auto utf8_name = entry->path().filename().u8string();
        const std::string profile_name {
          reinterpret_cast<const char *>(utf8_name.data()),
          utf8_name.size()
        };
        if (display_device::color_profile::is_valid_profile_basename(profile_name)) {
          profiles.push_back(profile_name);
        }
      }
      entry.increment(error);
    }

    if (error) {
      send_response(response, nlohmann::json {
        {"status", false},
        {"supported", true},
        {"profiles", nlohmann::json::array()},
        {"error", "failed to enumerate installed color profiles"},
      });
      return;
    }

    std::sort(profiles.begin(), profiles.end());
    send_response(response, nlohmann::json {
      {"status", true},
      {"supported", true},
      {"profiles", profiles},
    });
#else
    send_response(response, nlohmann::json {
      {"status", true},
      {"supported", false},
      {"profiles", nlohmann::json::array()},
    });
#endif
  }

  void
  closeApp(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    proc::proc.terminate();
    outputTree.put("status", true);
  }

  void
  write_runtime_error(resp_https_t response, SimpleWeb::StatusCode http_status, int status_code, const std::string &status_message) {
    json error_json;
    error_json["success"] = false;
    error_json["status_code"] = status_code;
    error_json["status_message"] = status_message;

    response->write(http_status, error_json.dump());
    response->close_connection_after_response = true;
  }

  bool
  require_localhost(resp_https_t response, req_https_t request, const std::string &action) {
    auto client_address = request->remote_endpoint().address();
    auto address = net::addr_to_normalized_string(client_address);
    auto ip_type = net::from_address(address);

    if (ip_type == net::PC) {
      return true;
    }

    std::ostringstream msg_stream;
    msg_stream << "Access denied when " << action << ". Only localhost requests are allowed. Client IP: " << client_address.to_string();
    BOOST_LOG(warning) << msg_stream.str();
    write_runtime_error(response, SimpleWeb::StatusCode::client_error_forbidden, 403, msg_stream.str());
    return false;
  }

  void
  getRuntimeSessions(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    if (!require_localhost(response, request, "getting runtime sessions")) {
      return;
    }

    try {
      // 获取所有活动会话信息
      auto sessions_info = stream::session::get_all_sessions_info();
      
      json response_json;
      response_json["success"] = true;
      response_json["status_code"] = 200;
      response_json["status_message"] = "Success";
      response_json["total_sessions"] = sessions_info.size();
      
      json sessions_array = json::array();

      for (const auto &session_info : sessions_info) {
        json session_obj;
        session_obj["client_name"] = session_info.client_name;
        session_obj["client_uuid"] = session_info.client_uuid;
        session_obj["client_address"] = session_info.client_address;
        session_obj["state"] = session_info.state;
        session_obj["session_id"] = session_info.session_id;
        session_obj["width"] = session_info.width;
        session_obj["height"] = session_info.height;
        session_obj["fps"] = session_info.fps;
        session_obj["bitrate"] = session_info.bitrate;
        session_obj["host_audio"] = session_info.host_audio;
        session_obj["enable_hdr"] = session_info.enable_hdr;
        session_obj["enable_mic"] = session_info.enable_mic;
        session_obj["use_vdd"] = session_info.use_vdd;
        session_obj["hdr_brightness_reported"] = session_info.hdr_brightness_reported;
        session_obj["hdr_brightness_source"] = session_info.hdr_brightness_source;
        session_obj["hdr_max_nits"] = session_info.hdr_max_nits;
        session_obj["hdr_min_nits"] = session_info.hdr_min_nits;
        session_obj["hdr_max_full_frame_nits"] = session_info.hdr_max_full_frame_nits;
        session_obj["app_name"] = session_info.app_name;
        session_obj["app_id"] = session_info.app_id;
        
        sessions_array.push_back(session_obj);
      }
      
      response_json["sessions"] = sessions_array;
      
      BOOST_LOG(debug) << "Config API: Runtime sessions info requested, returned " << sessions_info.size() << " sessions";
      
      response->write(response_json.dump());
      response->close_connection_after_response = true;
    }
    catch (const std::exception &e) {
      BOOST_LOG(error) << "getRuntimeSessions: " << e.what();
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, std::string(e.what()));
    }
    catch (...) {
      BOOST_LOG(error) << "getRuntimeSessions: Unknown exception";
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, "Unknown error");
    }
  }

  void
  getRuntimeHdrStatus(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    if (!require_localhost(response, request, "getting runtime HDR status")) {
      return;
    }

    try {
      const auto statuses = video::get_hdr_pipeline_statuses();
      const auto enhancement_status = image_enhancement::manager().status();
      json response_json {
        { "success", true },
        { "status_code", 200 },
        { "status_message", "Success" },
#ifdef _WIN32
        { "available", true },
#else
        { "available", false },
#endif
        { "configured_analysis_mode", config::video.hdr_luminance_analysis },
        { "configured_conversion_mode", config::video.capture_compute_shader },
        { "configured_hdr_backend", enhancement_status.value("selected_backend", std::string {}) },
        { "configured_nr_backend", enhancement_status.value("selected_nr_backend", std::string {}) },
        { "pipelines", json::array() },
      };

      for (const auto &status : statuses) {
        response_json["pipelines"].push_back({
          { "id", status.id },
          { "hdr_mode", status.hdr_mode },
          { "analysis_mode", status.analysis_mode },
          { "analysis_active", status.analysis_active },
          { "scene_metadata_active", status.scene_metadata_active },
          { "metadata_formats", status.metadata_formats },
          { "conversion_path", status.conversion_path },
          { "conversion_fallback_reason", status.conversion_fallback_reason },
          { "analysis_failure_reason", status.analysis_failure_reason },
          { "synthetic_hdr_backend", status.synthetic_hdr_backend },
          { "synthetic_hdr_state", status.synthetic_hdr_state },
          { "synthetic_hdr_failure_reason", status.synthetic_hdr_failure_reason },
          { "nr_backend", status.nr_backend },
          { "nr_state", status.nr_state },
          { "nr_failure_reason", status.nr_failure_reason },
        });
      }

      response->write(response_json.dump());
      response->close_connection_after_response = true;
    }
    catch (const std::exception &e) {
      BOOST_LOG(error) << "getRuntimeHdrStatus: " << e.what();
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, std::string(e.what()));
    }
    catch (...) {
      BOOST_LOG(error) << "getRuntimeHdrStatus: Unknown exception";
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, "Unknown error");
    }
  }

  void
  getRuntimeHdrCalibration(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);
    if (!require_localhost(response, request, "getting HDR calibration status")) return;

    try {
      json output {
        { "success", true },
        { "supported", false },
        { "vddActive", false },
        { "hdrEnabled", false },
        { "calibrated", false },
        { "profileName", nullptr },
        { "maxNits", nullptr },
        { "minNits", nullptr },
        { "maxFullFrameNits", nullptr },
        { "state", "unsupported" },
        { "sharedVdd", config::video.vdd_reuse },
        { "activeClients", json::array() },
      };

      for (const auto &session : stream::session::get_all_sessions_info()) {
        if (session.state == "RUNNING" && session.enable_hdr && session.use_vdd) {
          output["activeClients"].push_back({
            { "uuid", session.client_uuid },
            { "name", session.client_name },
          });
        }
      }

#ifdef _WIN32
      output["supported"] = true;
      const auto vdd_id = display_device::find_device_by_friendlyname(ZAKO_NAME);
      if (!vdd_id.empty()) {
        output["vddActive"] = true;
        const auto hdr_states = display_device::get_current_hdr_states({ vdd_id });
        const auto hdr_state = hdr_states.find(vdd_id);
        const bool hdr_enabled = hdr_state != hdr_states.end() &&
                                 hdr_state->second == display_device::hdr_state_e::enabled;
        output["hdrEnabled"] = hdr_enabled;
        output["state"] = hdr_enabled ? "ready" : "waiting_hdr";

        if (const auto calibration = display_device::win_color_profile::current_hdr_calibration(vdd_id)) {
          output["calibrated"] = true;
          output["profileName"] = calibration->profile_name;
          output["maxNits"] = calibration->max_nits;
          output["minNits"] = calibration->min_nits;
          output["maxFullFrameNits"] = calibration->max_full_frame_nits;
          output["state"] = "calibrated";
        }
      }
      else {
        output["state"] = "waiting_vdd";
      }
#endif

      send_response(response, output);
    }
    catch (const std::exception &e) {
      BOOST_LOG(error) << "getRuntimeHdrCalibration: " << e.what();
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, e.what());
    }
    catch (...) {
      BOOST_LOG(error) << "getRuntimeHdrCalibration: Unknown exception";
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, "Unknown error");
    }
  }

  void
  stopRuntimeSessions(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    if (!require_localhost(response, request, "stopping runtime sessions")) {
      return;
    }

    try {
      // 终止当前全部串流会话(所有客户端),语义与 Game Bar widget 的 stop_all_sessions 一致
      rtsp_stream::terminate_sessions_async(
        stream::session::stop_reason_e::host_terminate,
        boost::function<void()>([] {}));
      BOOST_LOG(info) << "Config API: session termination requested from local panel"sv;

      response->write(json {
                          { "success", true },
                          { "status_message", "session termination requested" },
                        }
                         .dump(),
        { { "Content-Type", "application/json" } });
      response->close_connection_after_response = true;
    }
    catch (const std::exception &e) {
      BOOST_LOG(error) << "stopRuntimeSessions: " << e.what();
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, e.what());
    }
    catch (...) {
      BOOST_LOG(error) << "stopRuntimeSessions: Unknown exception";
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, "Unknown error");
    }
  }

  void
  getPerfCurrent(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    if (!require_localhost(response, request, "getting performance snapshot")) {
      return;
    }

    try {
      response->write(perf::current_snapshot_json().dump());
      response->close_connection_after_response = true;
    }
    catch (const std::exception &e) {
      BOOST_LOG(error) << "getPerfCurrent: " << e.what();

      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, std::string(e.what()));
    }
    catch (...) {
      BOOST_LOG(error) << "getPerfCurrent: Unknown exception";
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, "Unknown error");
    }
  }

  void
  changeRuntimeBitrate(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    if (!require_localhost(response, request, "changing runtime bitrate")) {
      return;
    }

    try {
      auto args = request->parse_query_string();
      auto bitrate_param = args.find("bitrate");
      auto clientname_param = args.find("clientname");

      // 验证参数
      if (bitrate_param == args.end()) {
        std::ostringstream msg_stream;
        msg_stream << "Missing bitrate parameter when changing bitrate";
        BOOST_LOG(warning) << msg_stream.str();
        write_runtime_error(response, SimpleWeb::StatusCode::client_error_bad_request, 400, msg_stream.str());
        return;
      }

      if (clientname_param == args.end()) {
        std::ostringstream msg_stream;
        msg_stream << "Missing clientname parameter when changing bitrate";
        BOOST_LOG(warning) << msg_stream.str();
        write_runtime_error(response, SimpleWeb::StatusCode::client_error_bad_request, 400, msg_stream.str());
        return;
      }

      // 安全地解析码率参数
      int bitrate = 0;
      try {
        bitrate = std::stoi(bitrate_param->second);
      }
      catch (...) {
        write_runtime_error(response, SimpleWeb::StatusCode::client_error_bad_request, 400, "Invalid bitrate parameter format");
        return;
      }

      std::string client_name = clientname_param->second;

      // 验证码率范围
      if (bitrate <= 0 || bitrate > 800000) {
        std::ostringstream msg_stream;
        msg_stream << "Invalid bitrate value when changing bitrate. Must be between 1 and 800000 Kbps";
        BOOST_LOG(warning) << msg_stream.str();
        write_runtime_error(response, SimpleWeb::StatusCode::client_error_bad_request, 400, msg_stream.str());
        return;
      }

      // 获取所有活动会话以便调试
      std::vector<std::string> available_clients;
      try {
        auto sessions_info = stream::session::get_all_sessions_info();
        for (const auto &session_info : sessions_info) {
          if (session_info.state == "RUNNING") {
            available_clients.push_back(session_info.client_name);
          }
        }
      }
      catch (...) {
        // 继续执行，即使获取会话信息失败，仍然尝试修改码率
      }
      
      BOOST_LOG(info) << "Config API: Attempting to change bitrate for client '" << client_name 
                      << "' to " << bitrate << " Kbps";
      if (!available_clients.empty()) {
        BOOST_LOG(info) << "Available RUNNING clients: " << boost::algorithm::join(available_clients, ", ");
      }
      
      // 调用底层 API 修改码率
      video::dynamic_param_t param;
      param.type = video::dynamic_param_type_e::BITRATE;
      param.value.int_value = bitrate;
      param.valid = true;
      
      bool success = stream::session::change_dynamic_param_for_client(client_name, param);

      json response_json;
      if (success) {
        response_json["success"] = true;
        response_json["status_code"] = 200;
        response_json["status_message"] = "Bitrate change request sent to client session";
        response_json["bitrate"] = bitrate;
        response_json["client_name"] = client_name;
        
        BOOST_LOG(info) << "Config API: Dynamic bitrate change requested for client '" 
                       << client_name << "': " << bitrate << " Kbps";
      } else {
        std::string error_msg = "No active streaming session found for client: " + client_name;
        if (!available_clients.empty()) {
          error_msg += ". Available clients: " + boost::algorithm::join(available_clients, ", ");
        } else {
          error_msg += ". No RUNNING sessions available.";
        }
        
        response_json["success"] = false;
        response_json["status_code"] = 404;
        response_json["status_message"] = error_msg;
        
        BOOST_LOG(warning) << "Config API: Failed to change bitrate - " << error_msg;
      }
      
      response->write(
        success ? SimpleWeb::StatusCode::success_ok : SimpleWeb::StatusCode::client_error_not_found,
        response_json.dump()
      );
      response->close_connection_after_response = true;
    }
    catch (const std::exception &e) {
      BOOST_LOG(error) << "changeRuntimeBitrate: " << e.what();
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, std::string(e.what()));
    }
    catch (...) {
      BOOST_LOG(error) << "changeRuntimeBitrate: Unknown exception";
      write_runtime_error(response, SimpleWeb::StatusCode::server_error_internal_server_error, 500, "Unknown error");
    }
  }

  void
  proxySteamApi(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);

    // 提取请求路径，移除/steam-api前缀
    std::string path = request->path;
    if (path.find("/steam-api") == 0) {
      path = path.substr(10); // 移除"/steam-api"前缀
    }

    // 构建目标URL
    std::string targetUrl = "https://api.steampowered.com" + path;
    
    // 添加查询参数
    if (!request->query_string.empty()) {
      targetUrl += "?" + request->query_string;
    }

    BOOST_LOG(info) << "Steam API proxy request path: " << http_util::sanitize_request_log_value(path);

    // 安全检查：防止SSRF，确保目标主机确实是api.steampowered.com
    if (http::url_get_host(targetUrl) != "api.steampowered.com") {
      BOOST_LOG(warning) << "Blocked Steam API proxy request to unauthorized host";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Invalid Host");
      return;
    }

    // 使用http模块下载数据
    std::string content;
    
    try {
      if (http::fetch_url(targetUrl, content)) {
        // 设置响应头
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Content-Type", "application/json");
        
        response->write(SimpleWeb::StatusCode::success_ok, content, headers);
      } else {
        BOOST_LOG(error) << "Steam API request failed for path: " << http_util::sanitize_request_log_value(path);
        response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Steam API request failed");
      }
    } catch (const std::exception& e) {
      BOOST_LOG(error) << "Steam API proxy exception: " << e.what();
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Steam API proxy exception");
    }
  }

  void
  proxySteamStore(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);

    // 提取请求路径，移除/steam-store前缀
    std::string path = request->path;
    if (path.find("/steam-store") == 0) {
      path = path.substr(12); // 移除"/steam-store"前缀
    }

    // 构建目标URL
    std::string targetUrl = "https://store.steampowered.com" + path;
    
    // 添加查询参数
    if (!request->query_string.empty()) {
      targetUrl += "?" + request->query_string;
    }

    BOOST_LOG(info) << "Steam Store proxy request path: " << http_util::sanitize_request_log_value(path);

    // 安全检查：防止SSRF，确保目标主机确实是store.steampowered.com
    if (http::url_get_host(targetUrl) != "store.steampowered.com") {
      BOOST_LOG(warning) << "Blocked Steam Store proxy request to unauthorized host";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Invalid Host");
      return;
    }

    // 使用http模块下载数据
    std::string content;
    
    try {
      if (http::fetch_url(targetUrl, content)) {
        // 设置响应头
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Content-Type", "application/json");
        
        response->write(SimpleWeb::StatusCode::success_ok, content, headers);
      } else {
        BOOST_LOG(error) << "Steam Store request failed for path: " << http_util::sanitize_request_log_value(path);
        response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Steam Store request failed");
      }
    } catch (const std::exception& e) {
      BOOST_LOG(error) << "Steam Store proxy exception: " << e.what();
      response->write(SimpleWeb::StatusCode::server_error_internal_server_error, "Steam Store proxy exception");
    }
  }

  // ===== AI LLM Proxy =====

  // 内存缓存 AI 配置，避免每次请求都读文件
  static std::mutex ai_config_mutex;
  static nlohmann::json ai_config_cache;
  static bool ai_config_loaded = false;

  /**
   * @brief 获取 AI 配置文件路径（与 sunshine.conf 同目录）
   */
  static fs::path
  getAiConfigPath() {
    auto config_dir = file_handler::path_from_utf8(config::sunshine.config_file).parent_path();
    return config_dir / "ai_config.json";
  }

  static fs::path
  getAiCredentialPath() {
    auto config_dir = file_handler::path_from_utf8(config::sunshine.config_file).parent_path();
    return config_dir / "ai_llm_credential.bin";
  }

  static void
  applyStoredCredentialLocked(nlohmann::json &cfg) {
    auto credential = credential_store::read_llm_api_key(getAiCredentialPath());
    if (credential.status == credential_store::read_status_e::success) {
      cfg["apiKey"] = std::move(credential.secret);
    } else {
      cfg["apiKey"] = "";
      if (credential.status == credential_store::read_status_e::error) {
        BOOST_LOG(error) << "Could not load the LLM API key from secure storage: " << credential.error;
      }
    }
    cfg["apiKeyConfigured"] = !cfg.value("apiKey", "").empty();
  }

  static bool
  writeAiConfigFile(const nlohmann::json &cfg) {
    const fs::path path = getAiConfigPath();
    auto temp = path;
    temp += ".tmp";
    try {
      {
        std::ofstream file(temp, std::ios::trunc);
        if (!file.is_open()) return false;
        file << cfg.dump(2);
        file.flush();
        if (!file.good()) throw std::runtime_error("Failed to flush AI config");
      }
#ifdef _WIN32
      if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::error_code ignored;
        fs::remove(temp, ignored);
        return false;
      }
#else
      std::error_code ec;
      fs::rename(temp, path, ec);
      if (ec) {
        fs::remove(temp, ec);
        return false;
      }
#endif
      return true;
    } catch (const std::exception &e) {
      std::error_code ignored;
      fs::remove(temp, ignored);
      BOOST_LOG(error) << "Failed to save AI config: " << e.what();
      return false;
    }
  }

  /**
   * @brief 从文件或缓存读取 AI 配置（调用方需持有 ai_config_mutex）
   */
  static nlohmann::json
  loadAiConfigLocked() {
    if (ai_config_loaded) {
      return ai_config_cache;
    }

    auto path = getAiConfigPath();
    try {
      const auto utf8_path = file_handler::path_to_utf8(path);
      std::string content = file_handler::read_file(utf8_path.c_str());
      if (!content.empty()) {
        auto persisted = nlohmann::json::parse(content);
        ai_config_cache = persisted;

        // Migrate legacy plaintext credentials before exposing the runtime
        // configuration. Never remove the old value until both secure storage
        // and the sanitized config rewrite have succeeded.
        const std::string legacy_key = persisted.value("apiKey", "");
        if (!legacy_key.empty()) {
          auto migration = credential_store::write_llm_api_key(getAiCredentialPath(), legacy_key);
          if (migration.success) {
            auto sanitized = persisted;
            sanitized.erase("apiKey");
            if (writeAiConfigFile(sanitized)) {
              ai_config_cache = std::move(sanitized);
              BOOST_LOG(info) << "Migrated the LLM API key out of ai_config.json";
            } else {
              BOOST_LOG(error) << "The LLM API key was secured, but ai_config.json could not be sanitized; migration will retry";
            }
          } else {
            BOOST_LOG(error) << "Could not migrate the plaintext LLM API key: " << migration.error;
          }
          ai_config_cache["apiKey"] = legacy_key;
        } else {
          applyStoredCredentialLocked(ai_config_cache);
        }
        ai_config_cache["apiKeyConfigured"] = !ai_config_cache.value("apiKey", "").empty();
        ai_config_loaded = true;
        return ai_config_cache;
      }
    } catch (...) {}

    ai_config_cache = nlohmann::json{
      {"enabled", false},
      {"provider", "openai"},
      {"apiBase", "https://api.openai.com/v1"},
      {"apiKey", ""},
      {"apiKeyConfigured", false},
      {"model", "gpt-4.1-mini"},
      {"compatibility", "openai-chat"},
      {"temperature", 0.3},
      {"max_tokens", 2048}
    };
    applyStoredCredentialLocked(ai_config_cache);
    ai_config_loaded = true;
    return ai_config_cache;
  }

  /**
   * @brief 从文件或缓存读取 AI 配置（线程安全）
   */
  static nlohmann::json
  loadAiConfig() {
    std::lock_guard<std::mutex> lock(ai_config_mutex);
    return loadAiConfigLocked();
  }

  /**
   * @brief 保存 AI 配置并刷新缓存（调用方需持有 ai_config_mutex）
   */
  static bool
  saveAiConfigLocked(const nlohmann::json &cfg) {
    auto persisted = cfg;
    persisted.erase("apiKey");
    persisted.erase("apiKeyConfigured");
    persisted.erase("apiKeyHint");
    if (!writeAiConfigFile(persisted)) return false;
    ai_config_cache = cfg;
    ai_config_loaded = true;
    return true;
  }

  /**
   * @brief 检测 provider 是否为 Anthropic（需要不同的 API 格式）
   */
  static bool
  isAnthropicProvider(const nlohmann::json &cfg) {
    std::string compatibility = cfg.value("compatibility", "");
    std::string provider = cfg.value("provider", "");
    std::string apiBase = cfg.value("apiBase", "");
    return compatibility == "anthropic-messages" || provider == "anthropic" || apiBase.find("anthropic.com") != std::string::npos;
  }

  static bool
  isApiKeyRequired(const nlohmann::json &cfg) {
    std::string provider = cfg.value("provider", "");
    std::string apiBase = cfg.value("apiBase", "");
    return provider != "ollama" &&
           apiBase.find("localhost") == std::string::npos &&
           apiBase.find("127.0.0.1") == std::string::npos &&
           apiBase.find("[::1]") == std::string::npos;
  }

  static bool
  hasSuffix(const std::string &value, const std::string &suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
  }

  static std::string
  buildAiEndpoint(std::string apiBase, bool isAnthropic) {
    while (!apiBase.empty() && apiBase.back() == '/') {
      apiBase.pop_back();
    }

    if (isAnthropic) {
      if (hasSuffix(apiBase, "/v1/messages") || hasSuffix(apiBase, "/messages")) {
        return apiBase;
      }
      if (hasSuffix(apiBase, "/v1")) {
        return apiBase + "/messages";
      }
      return apiBase + "/v1/messages";
    }

    if (hasSuffix(apiBase, "/chat/completions")) {
      return apiBase;
    }
    return apiBase + "/chat/completions";
  }

  /**
   * @brief 将 OpenAI 格式的请求转换为 Anthropic 格式
   */
  static std::string
  convertToAnthropicFormat(const std::string &openaiBody, const std::string &model) {
    try {
      auto input = nlohmann::json::parse(openaiBody);
      nlohmann::json anthropic;

      anthropic["model"] = input.value("model", model);
      anthropic["max_tokens"] = input.value("max_tokens", 4096);

      // 提取 system message 和 user/assistant messages
      if (input.contains("messages")) {
        nlohmann::json messages = nlohmann::json::array();
        for (auto &msg : input["messages"]) {
          std::string role = msg.value("role", "");
          if (role == "system") {
            anthropic["system"] = msg.value("content", "");
          } else {
            messages.push_back(msg);
          }
        }
        anthropic["messages"] = messages;
      }

      // 转换 temperature, top_p 等通用参数
      if (input.contains("temperature")) anthropic["temperature"] = input["temperature"];
      if (input.contains("top_p")) anthropic["top_p"] = input["top_p"];
      if (input.contains("stream")) anthropic["stream"] = input["stream"];

      return anthropic.dump();
    } catch (...) {
      return openaiBody;  // 转换失败，原样返回
    }
  }

  /**
   * @brief 将 Anthropic 格式的响应转换回 OpenAI 格式
   */
  static std::string
  convertFromAnthropicFormat(const std::string &anthropicResponse) {
    try {
      auto resp = nlohmann::json::parse(anthropicResponse);
      nlohmann::json openai;

      openai["id"] = resp.value("id", "");
      openai["object"] = "chat.completion";
      openai["model"] = resp.value("model", "");

      // 转换 content blocks
      nlohmann::json choice;
      choice["index"] = 0;
      choice["finish_reason"] = resp.value("stop_reason", "stop");

      std::string content;
      if (resp.contains("content") && resp["content"].is_array()) {
        for (auto &block : resp["content"]) {
          if (block.value("type", "") == "text") {
            content += block.value("text", "");
          }
        }
      }
      choice["message"]["role"] = "assistant";
      choice["message"]["content"] = content;
      openai["choices"] = nlohmann::json::array({choice});

      // 转换 usage
      if (resp.contains("usage")) {
        openai["usage"]["prompt_tokens"] = resp["usage"].value("input_tokens", 0);
        openai["usage"]["completion_tokens"] = resp["usage"].value("output_tokens", 0);
        openai["usage"]["total_tokens"] =
          resp["usage"].value("input_tokens", 0) + resp["usage"].value("output_tokens", 0);
      }

      return openai.dump();
    } catch (...) {
      return anthropicResponse;
    }
  }

  SimpleWeb::CaseInsensitiveMultimap
  json_headers() {
    return {
      { "Content-Type", "application/json" },
      { "Cache-Control", "no-store" },
      { "X-Content-Type-Options", "nosniff" }
    };
  }

  void
  write_json(resp_https_t response, SimpleWeb::StatusCode status, const json &body) {
    response->write(status, body.dump(), json_headers());
  }

  void
  write_json_error(resp_https_t response, SimpleWeb::StatusCode status, std::string error) {
    json body;
    body["ok"] = false;
    body["error"] = std::move(error);
    write_json(std::move(response), status, body);
  }

  bool
  read_json_body(resp_https_t response, req_https_t request, json &body) {
    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      body = json::parse(ss.str());
      return true;
    }
    catch (const std::exception &e) {
      write_json_error(std::move(response), SimpleWeb::StatusCode::client_error_bad_request, std::string { "Invalid JSON: " } + e.what());
      return false;
    }
  }

  bool
  persistFileMappingStoreOrRestore(std::vector<file_mapping::mapping_t> previous_mappings) {
    if (file_mapping_store::persist_to_config(file_mapping_store::global())) {
      return true;
    }

    file_mapping_store::global().replace(std::move(previous_mappings));
    return false;
  }

  void
  listFileMappings(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);

    json body;
    body["ok"] = true;
    body["mappings"] = file_mapping_store::global().to_json();
    write_json(std::move(response), SimpleWeb::StatusCode::success_ok, body);
  }

  void
  createFileMapping(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;
    print_req(request);

    json input;
    if (!read_json_body(response, request, input)) return;
    if (!input.is_object() || !input.contains("path") || !input["path"].is_string()) {
      write_json_error(std::move(response), SimpleWeb::StatusCode::client_error_bad_request, "missing string field: path");
      return;
    }

    file_mapping_store::mutation_result_t result;
    {
      std::scoped_lock transaction_lock { file_mapping_store_transaction_mutex };
      auto previous_mappings = file_mapping_store::global().snapshot();
      result = file_mapping_store::global().add_quick_share(input["path"].get<std::string>());
      if (!result.ok) {
        write_json_error(std::move(response), SimpleWeb::StatusCode::client_error_bad_request, result.error);
        return;
      }
      if (!persistFileMappingStoreOrRestore(std::move(previous_mappings))) {
        write_json_error(std::move(response), SimpleWeb::StatusCode::server_error_internal_server_error, "failed to persist mapping configuration");
        return;
      }
    }

    json body;
    body["ok"] = true;
    body["mapping"] = file_mapping_store::mapping_to_config_json(result.mapping);
    write_json(std::move(response), SimpleWeb::StatusCode::success_ok, body);
  }

  void
  updateFileMapping(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;
    print_req(request);

    const auto id = request->path_match.size() > 1 ? request->path_match[1].str() : std::string {};
    if (!file_mapping::is_valid_mapping_id(id)) {
      write_json_error(std::move(response), SimpleWeb::StatusCode::client_error_bad_request, "invalid mapping id");
      return;
    }

    json input;
    if (!read_json_body(response, request, input)) return;
    file_mapping_store::mutation_result_t result;
    {
      std::scoped_lock transaction_lock { file_mapping_store_transaction_mutex };
      auto previous_mappings = file_mapping_store::global().snapshot();
      result = file_mapping_store::global().update(id, input);
      if (!result.ok) {
        const auto status = result.error == "mapping was not found" ? SimpleWeb::StatusCode::client_error_not_found : SimpleWeb::StatusCode::client_error_bad_request;
        write_json_error(std::move(response), status, result.error);
        return;
      }
      if (!persistFileMappingStoreOrRestore(std::move(previous_mappings))) {
        write_json_error(std::move(response), SimpleWeb::StatusCode::server_error_internal_server_error, "failed to persist mapping configuration");
        return;
      }
    }

    json body;
    body["ok"] = true;
    body["mapping"] = file_mapping_store::mapping_to_config_json(result.mapping);
    write_json(std::move(response), SimpleWeb::StatusCode::success_ok, body);
  }

  void
  deleteFileMapping(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);

    const auto id = request->path_match.size() > 1 ? request->path_match[1].str() : std::string {};
    if (!file_mapping::is_valid_mapping_id(id)) {
      write_json_error(std::move(response), SimpleWeb::StatusCode::client_error_bad_request, "invalid mapping id");
      return;
    }
    {
      std::scoped_lock transaction_lock { file_mapping_store_transaction_mutex };
      auto previous_mappings = file_mapping_store::global().snapshot();
      if (!file_mapping_store::global().remove(id)) {
        write_json_error(std::move(response), SimpleWeb::StatusCode::client_error_not_found, "mapping was not found");
        return;
      }
      if (!persistFileMappingStoreOrRestore(std::move(previous_mappings))) {
        write_json_error(std::move(response), SimpleWeb::StatusCode::server_error_internal_server_error, "failed to persist mapping configuration");
        return;
      }
    }

    json body;
    body["ok"] = true;
    body["id"] = id;
    write_json(std::move(response), SimpleWeb::StatusCode::success_ok, body);
  }

  /**
   * @brief GET /api/ai/config — 获取 AI 配置（不返回完整 API key）
   */
  void
  getAiConfig(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);

    auto cfg = loadAiConfig();

    // Never expose the key; only report whether one is configured.
    const std::string key = cfg.value("apiKey", "");
    cfg.erase("apiKey");
    cfg["apiKeyConfigured"] = !key.empty();

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(SimpleWeb::StatusCode::success_ok, cfg.dump(), headers);
  }

  /**
   * @brief POST /api/ai/config — 保存 AI 配置
   */
  void
  saveAiConfigEndpoint(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;
    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    nlohmann::json output;
    try {
      auto input = nlohmann::json::parse(ss.str());

      // 用同一把锁包住 load-modify-save，防止并发写入丢失
      std::lock_guard<std::mutex> lock(ai_config_mutex);
      auto current = loadAiConfigLocked();
      if (input.contains("enabled")) current["enabled"] = input["enabled"].get<bool>();
      if (input.contains("provider")) current["provider"] = input["provider"].get<std::string>();
      if (input.contains("apiBase")) current["apiBase"] = input["apiBase"].get<std::string>();
      if (input.contains("model")) current["model"] = input["model"].get<std::string>();
      if (input.contains("compatibility")) current["compatibility"] = input["compatibility"].get<std::string>();
      if (input.contains("system_prompt")) current["system_prompt"] = input["system_prompt"].get<std::string>();
      if (input.contains("temperature")) current["temperature"] = input["temperature"].get<double>();
      if (input.contains("max_tokens")) current["max_tokens"] = input["max_tokens"].get<int>();
      std::string key_action = input.value("apiKeyAction", "keep");
      // Backward compatibility for older clients that only send apiKey.
      if (input.contains("apiKey") && key_action == "keep") {
        const std::string candidate = input["apiKey"].get<std::string>();
        if (!candidate.empty() && candidate.find("****") == std::string::npos) {
          key_action = "replace";
        }
      }

      if (key_action == "replace") {
        if (!input.contains("apiKey") || !input["apiKey"].is_string() || input["apiKey"].get_ref<const std::string &>().empty()) {
          throw std::invalid_argument("apiKeyAction=replace requires a non-empty apiKey");
        }
        const std::string key = input["apiKey"].get<std::string>();
        auto stored = credential_store::write_llm_api_key(getAiCredentialPath(), key);
        if (!stored.success) throw std::runtime_error("Failed to secure API key: " + stored.error);
        current["apiKey"] = key;
      } else if (key_action == "clear") {
        auto erased = credential_store::erase_llm_api_key(getAiCredentialPath());
        if (!erased.success) throw std::runtime_error("Failed to clear API key: " + erased.error);
        current["apiKey"] = "";
      } else if (key_action != "keep") {
        throw std::invalid_argument("apiKeyAction must be keep, replace, or clear");
      }
      current["apiKeyConfigured"] = !current.value("apiKey", "").empty();

      if (saveAiConfigLocked(current)) {
        output["status"] = "ok";
        output["apiKeyConfigured"] = current["apiKeyConfigured"];
      } else {
        output["status"] = "error";
        output["error"] = "Failed to write config file";
        // Credential mutations have already completed. Keep runtime behavior
        // consistent with secure storage even if the non-secret JSON write
        // failed; the caller still receives an error and can retry.
        ai_config_cache = current;
        ai_config_loaded = true;
      }
    } catch (const std::exception &e) {
      output["status"] = "error";
      output["error"] = e.what();
    }

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(SimpleWeb::StatusCode::success_ok, output.dump(), headers);
  }

  void
  proxyAiModels(resp_https_t response, req_https_t request) {
    if (!authenticate(response, request)) return;
    print_req(request);

    const auto cfg = loadAiConfig();
    if (!cfg.value("enabled", false)) {
      response->write(
        SimpleWeb::StatusCode::client_error_forbidden,
        R"({"error":{"message":"AI proxy is not enabled","type":"invalid_request_error"}})",
        json_headers());
      return;
    }
    const std::string api_key = cfg.value("apiKey", "");
    std::string api_base = cfg.value("apiBase", "");
    if (api_base.empty() || (api_key.empty() && isApiKeyRequired(cfg))) {
      response->write(
        SimpleWeb::StatusCode::client_error_bad_request,
        R"({"error":{"message":"AI proxy not configured","type":"invalid_request_error"}})",
        json_headers());
      return;
    }
    if (isAnthropicProvider(cfg)) {
      response->write(SimpleWeb::StatusCode::success_ok, R"({"data":[]})", json_headers());
      return;
    }

    while (!api_base.empty() && api_base.back() == '/') api_base.pop_back();
    if (hasSuffix(api_base, "/chat/completions")) {
      api_base.resize(api_base.size() - std::string_view { "/chat/completions" }.size());
    }
    const std::string target_url = api_base + "/models";
    std::map<std::string, std::string> headers;
    if (!api_key.empty()) headers["Authorization"] = "Bearer " + api_key;

    std::string body;
    long http_code = 0;
    if (!http::get_json(target_url, headers, body, http_code)) {
      response->write(
        SimpleWeb::StatusCode::server_error_bad_gateway,
        R"({"error":{"message":"Failed to connect to upstream LLM API","type":"upstream_error"}})",
        json_headers());
      return;
    }
    const auto status = http_code >= 200 && http_code < 300
                          ? SimpleWeb::StatusCode::success_ok
                          : SimpleWeb::StatusCode::server_error_bad_gateway;
    response->write(status, body, json_headers());
  }

  /**
   * @brief POST /api/ai/chat/completions — OpenAI 兼容的 LLM 代理端点
   *
   * 支持普通请求和 SSE 流式请求。
   * 自动适配 Anthropic API 格式。
   * 客户端无需知道 API key 或实际后端，Sunshine 作为透明代理。
   */
  void
  proxyAiChat(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;
    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    std::string requestBody = ss.str();

    // 检测是否请求流式输出
    bool isStream = false;
    try {
      auto reqJson = nlohmann::json::parse(requestBody);
      isStream = reqJson.value("stream", false);
    } catch (...) {}

    if (isStream) {
      bool headerSent = false;
      auto result = processAiChatStream(requestBody, [&](const char *data, size_t len) {
        if (!headerSent) {
          *response << "HTTP/1.1 200 OK\r\n";
          *response << "Content-Type: text/event-stream\r\n";
          *response << "Cache-Control: no-cache\r\n";
          *response << "Connection: keep-alive\r\n";
          *response << "\r\n";
          response->send();
          headerSent = true;
        }
        std::string chunk(data, len);
        *response << chunk;
        response->send();
      });

      if (result.httpCode != 200 && !headerSent) {
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Content-Type", "application/json");
        response->write(SimpleWeb::StatusCode::server_error_bad_gateway, result.body, headers);
      }
    } else {
      auto result = processAiChat(requestBody);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", result.contentType);

      auto statusCode = (result.httpCode == 200)
        ? SimpleWeb::StatusCode::success_ok
        : (result.httpCode == 403)
          ? SimpleWeb::StatusCode::client_error_forbidden
          : (result.httpCode == 400)
            ? SimpleWeb::StatusCode::client_error_bad_request
            : SimpleWeb::StatusCode::server_error_bad_gateway;

      response->write(statusCode, result.body, headers);
    }
  }

  /**
   * @brief OPTIONS handler for CORS preflight on AI endpoints
   */
  void
  handleAiCors(resp_https_t response, req_https_t request) {
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.emplace("Access-Control-Allow-Headers", "Content-Type, Authorization");
    response->write(SimpleWeb::StatusCode::success_no_content, "", headers);
  }

  // ===== AI Proxy shared interface =====

  bool
  isAiEnabled() {
    auto cfg = loadAiConfig();
    return cfg.value("enabled", false) &&
           (!isApiKeyRequired(cfg) || !cfg.value("apiKey", "").empty()) &&
           !cfg.value("apiBase", "").empty();
  }

  /**
   * @brief Prepare AI proxy request: validate config, build URL, headers, convert body.
   * @return empty targetUrl on error (result is filled with error info)
   */
  static bool
  prepareAiRequest(
    const std::string &requestBody,
    std::string &targetUrl,
    std::string &processedBody,
    std::map<std::string, std::string> &proxyHeaders,
    bool &isAnthropic,
    bool &isStream,
    AiProxyResult &result) {

    auto cfg = loadAiConfig();

    if (!cfg.value("enabled", false)) {
      result = {403, R"({"error":{"message":"AI proxy is not enabled","type":"invalid_request_error"}})", "application/json"};
      return false;
    }

    std::string apiBase = cfg.value("apiBase", "");
    std::string apiKey = cfg.value("apiKey", "");
    std::string defaultModel = cfg.value("model", "");

    if (apiBase.empty() || (apiKey.empty() && isApiKeyRequired(cfg))) {
      result = {400, R"({"error":{"message":"AI proxy not configured: missing apiBase or apiKey","type":"invalid_request_error"}})", "application/json"};
      return false;
    }

    if (requestBody.empty()) {
      result = {400, R"({"error":{"message":"Empty request body","type":"invalid_request_error"}})", "application/json"};
      return false;
    }

    processedBody = requestBody;
    isStream = false;

    try {
      auto reqJson = nlohmann::json::parse(processedBody);
      isStream = reqJson.value("stream", false);
      if (!reqJson.contains("model") && !defaultModel.empty()) {
        reqJson["model"] = defaultModel;
        processedBody = reqJson.dump();
      }
    } catch (...) {}

    isAnthropic = isAnthropicProvider(cfg);

    targetUrl = buildAiEndpoint(apiBase, isAnthropic);

    if (isAnthropic) {
      // Anthropic 流式 SSE 格式与 OpenAI 不兼容，强制走非流式以保证响应格式一致
      if (isStream) {
        try {
          auto reqJson = nlohmann::json::parse(processedBody);
          reqJson["stream"] = false;
          processedBody = reqJson.dump();
        } catch (...) {}
        isStream = false;
      }
      processedBody = convertToAnthropicFormat(processedBody, defaultModel);
      if (!apiKey.empty()) {
        proxyHeaders["x-api-key"] = apiKey;
      }
      proxyHeaders["anthropic-version"] = "2023-06-01";
    } else {
      if (!apiKey.empty()) {
        proxyHeaders["Authorization"] = "Bearer " + apiKey;
      }
    }

    BOOST_LOG(info) << "AI proxy forwarding to: " << targetUrl << (isStream ? " (stream)" : "");
    return true;
  }

  AiProxyResult
  processAiChat(const std::string &requestBody) {
    std::string targetUrl, processedBody;
    std::map<std::string, std::string> proxyHeaders;
    bool isAnthropic = false, isStream = false;
    AiProxyResult result;

    if (!prepareAiRequest(requestBody, targetUrl, processedBody, proxyHeaders, isAnthropic, isStream, result)) {
      return result;
    }

    std::string responseBody;
    long httpCode = 0;

    try {
      bool ok = http::post_json(targetUrl, processedBody, proxyHeaders, responseBody, httpCode, 120);
      if (ok) {
        if (isAnthropic && httpCode >= 200 && httpCode < 300) {
          responseBody = convertFromAnthropicFormat(responseBody);
        }
        int statusCode = (httpCode >= 200 && httpCode < 300) ? 200 : 502;
        return {statusCode, responseBody, "application/json"};
      } else {
        return {502, R"({"error":{"message":"Failed to connect to upstream LLM API","type":"upstream_error"}})", "application/json"};
      }
    } catch (const std::exception &e) {
      BOOST_LOG(error) << "AI proxy exception: " << e.what();
      nlohmann::json err;
      err["error"]["message"] = std::string("AI proxy exception: ") + e.what();
      err["error"]["type"] = "internal_error";
      return {500, err.dump(), "application/json"};
    }
  }

  /**
   * @brief curl write callback for streaming with std::function
   */
  struct StreamCallbackContext {
    std::function<void(const char *, size_t)> callback;
  };

  static size_t
  stream_func_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    auto *ctx = static_cast<StreamCallbackContext *>(userdata);
    ctx->callback(ptr, realsize);
    return realsize;
  }

  AiProxyResult
  processAiChatStream(
    const std::string &requestBody,
    std::function<void(const char *, size_t)> chunkCallback) {

    std::string targetUrl, processedBody;
    std::map<std::string, std::string> proxyHeaders;
    bool isAnthropic = false, isStream = false;
    AiProxyResult result;

    if (!prepareAiRequest(requestBody, targetUrl, processedBody, proxyHeaders, isAnthropic, isStream, result)) {
      return result;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
      return {500, R"({"error":{"message":"Failed to initialize CURL","type":"internal_error"}})", "application/json"};
    }

    StreamCallbackContext ctx;
    ctx.callback = std::move(chunkCallback);

    struct curl_slist *header_list = nullptr;
    header_list = curl_slist_append(header_list, "Content-Type: application/json");
    for (const auto &[key, value] : proxyHeaders) {
      std::string header_line = key + ": " + value;
      header_list = curl_slist_append(header_list, header_line.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, targetUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, processedBody.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(processedBody.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_func_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    CURLcode curlResult = curl_easy_perform(curl);
    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);

    if (curlResult != CURLE_OK) {
      return {502, R"({"error":{"message":"Failed to connect to upstream LLM API","type":"upstream_error"}})", "application/json"};
    }
    return {200, "", "text/event-stream"};
  }

  /**
   * @brief 计算文件的SHA256哈希值
   * @param filepath 文件路径
   * @return SHA256哈希字符串，如果失败返回空字符串
   */
  std::string
  calculate_file_hash(const std::string &filepath) {
    const auto native_path = file_handler::path_from_utf8(filepath);
    if (filepath.empty() || !fs::exists(native_path)) {
      return "";
    }

    std::ifstream file(native_path, std::ios::binary);
    if (!file.is_open()) {
      return "";
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
      return "";
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    char buf[1024 * 16];
    while (file.good()) {
      file.read(buf, sizeof(buf));
      if (file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buf, file.gcount()) != 1) {
          EVP_MD_CTX_free(mdctx);
          file.close();
          return "";
        }
      }
    }
    file.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
      EVP_MD_CTX_free(mdctx);
      return "";
    }
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; i++) {
      ss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return ss.str();
  }

  /**
   * @brief 从命令字符串中提取可执行文件路径
   * @param cmd 完整命令字符串
   * @return 可执行文件路径
   */
  std::string
  extract_executable_path(const std::string &cmd) {
    if (cmd.empty()) {
      return "";
    }

    std::string trimmed = cmd;
    // 移除前导空格
    size_t start = trimmed.find_first_not_of(" \t");
    if (start != std::string::npos) {
      trimmed = trimmed.substr(start);
    }

    // 处理引号包裹的路径
    if (!trimmed.empty() && trimmed[0] == '"') {
      size_t end = trimmed.find('"', 1);
      if (end != std::string::npos) {
        return trimmed.substr(1, end - 1);
      }
    }

    // 提取第一个空格前的部分（可执行文件路径）
    size_t space = trimmed.find(' ');
    if (space != std::string::npos) {
      return trimmed.substr(0, space);
    }

    return trimmed;
  }

  void
  testMenuCmd(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) return;
    if (!authenticate(response, request)) return;

    constexpr bool test_command_enabled = false;
    if (!test_command_enabled) {
      const nlohmann::json body {
        { "status", false },
        { "error", "Test command execution is temporarily disabled" },
        { "error_code", "TEST_COMMAND_DISABLED" },
      };
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", "application/json");
      response->write(SimpleWeb::StatusCode::server_error_service_unavailable, body.dump(), headers);
      return;
    }

    // 安全限制：只允许局域网访问测试命令功能
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    auto ip_type = net::from_address(address);
    
    if (ip_type != net::PC) {
      BOOST_LOG(warning) << "TestMenuCmd: Access denied from non-local network: " << address;
      pt::ptree outputTree;
      outputTree.put("status", false);
      outputTree.put("error", "Test command feature is only available from local network");
      
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      pt::read_json(ss, inputTree);
      auto cmd = inputTree.get<std::string>("cmd");
      auto working_dir = inputTree.get<std::string>("working_dir", "");
      auto elevated = inputTree.get<bool>("elevated", false);

      // 安全检查：命令不能为空
      if (cmd.empty()) {
        BOOST_LOG(warning) << "TestMenuCmd: Empty command provided";
        outputTree.put("status", false);
        outputTree.put("error", "Command cannot be empty");
        return;
      }

      // 安全检查：命令长度限制（防止过长的命令）
      if (cmd.length() > 4096) {
        BOOST_LOG(warning) << "TestMenuCmd: Command too long (" << cmd.length() << " characters)";
        outputTree.put("status", false);
        outputTree.put("error", "Command exceeds maximum length");
        return;
      }

      // 提取可执行文件路径并计算SHA256哈希值
      std::string executable_path = extract_executable_path(cmd);
      std::string file_hash;
      
      if (!executable_path.empty()) {
        // 如果是相对路径，尝试解析为绝对路径
        auto exec_path = file_handler::path_from_utf8(executable_path);
        if (!exec_path.is_absolute()) {
          // 在PATH中查找或使用工作目录
          if (!working_dir.empty()) {
            exec_path = file_handler::path_from_utf8(working_dir) / exec_path;
          }
        }
        
        file_hash = calculate_file_hash(file_handler::path_to_utf8(exec_path));
        
        if (file_hash.empty() && fs::exists(exec_path)) {
          BOOST_LOG(warning) << "TestMenuCmd: Failed to calculate hash for executable: " << file_handler::path_to_utf8(exec_path);
        }
      }

      // 记录详细信息用于审计（包含文件哈希值）
      BOOST_LOG(info) << "Testing menu command from " << address << ": [" << cmd << "]";
      if (!file_hash.empty()) {
        BOOST_LOG(info) << "Executable SHA256: " << file_hash << " (" << executable_path << ")";
      }
      else if (!executable_path.empty()) {
        BOOST_LOG(warning) << "Could not verify executable: " << executable_path;
      }

      std::error_code ec;
      boost::filesystem::path work_dir;
      
      if (!working_dir.empty()) {
        const auto native_working_dir = file_handler::path_from_utf8(working_dir);
        // 验证工作目录是否存在
        if (!fs::exists(native_working_dir) || !fs::is_directory(native_working_dir)) {
          BOOST_LOG(warning) << "TestMenuCmd: Invalid working directory: " << working_dir;
          outputTree.put("status", false);
          outputTree.put("error", "Invalid working directory");
          return;
        }
#ifdef _WIN32
        work_dir = boost::filesystem::path(native_working_dir.wstring());
#else
        work_dir = boost::filesystem::path(native_working_dir.string());
#endif
      } else {
        work_dir = boost::filesystem::current_path();
      }

      // 执行命令
      auto child = platf::run_command(elevated, true, cmd, work_dir, proc::proc.get_env(), nullptr, ec, nullptr);
      
      if (ec) {
        BOOST_LOG(warning) << "Failed to run menu command [" << cmd << "]: " << ec.message();
        outputTree.put("status", false);
        outputTree.put("error", "Failed to execute command: " + ec.message());
      }
      else {
        BOOST_LOG(info) << "Successfully executed menu command [" << cmd << "]";
        child.detach();
        outputTree.put("status", true);
        outputTree.put("message", "Command executed successfully");
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "TestMenuCmd error: " << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  start() {
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_https = net::map_port(PORT_HTTPS);
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    https_server_t server { config::nvhttp.cert, config::nvhttp.pkey };
    server.default_resource["GET"] = close_connection;
    server.resource["^/$"]["GET"] = getIndexPage;
    server.resource["^/pin/?$"]["GET"] = getPinPage;
    server.resource["^/apps/?$"]["GET"] = getAppsPage;
    server.resource["^/clients/?$"]["GET"] = getClientsPage;
    server.resource["^/config/?$"]["GET"] = getConfigPage;
    server.resource["^/password/?$"]["GET"] = getPasswordPage;
    server.resource["^/welcome/?$"]["GET"] = getWelcomePage;
    server.resource["^/troubleshooting/?$"]["GET"] = getTroubleshootingPage;
    server.resource["^/api/pin$"]["POST"] = savePin;
    server.resource["^/api/qr-pair$"]["POST"] = generateQrPairInfo;
    server.resource["^/api/qr-pair/cancel$"]["POST"] = cancelQrPair;
    server.resource["^/api/qr-pair$"]["GET"] = getQrPairStatus;
    server.resource["^/api/apps$"]["GET"] = getApps;
    server.resource["^/api/logs$"]["GET"] = getLogs;
    server.resource["^/api/apps$"]["POST"] = saveApp;
    server.resource["^/api/config$"]["GET"] = getConfig;
    server.resource["^/api/config$"]["POST"] = saveConfig;
    server.resource["^/api/gamepad/config$"]["GET"] = getGamepadConfig;
    server.resource["^/api/gamepad/config$"]["POST"] = saveGamepadConfig;
    server.resource["^/api/hdr-enhanced/config$"]["GET"] = getImageEnhancementConfig;
    server.resource["^/api/hdr-enhanced/config$"]["POST"] = saveImageEnhancementConfig;
    server.resource["^/api/hdr-enhanced/status$"]["GET"] = getImageEnhancementStatus;
    server.resource["^/api/hdr-enhanced/sessions$"]["GET"] = getEnhancementSessions;
    server.resource["^/api/hdr-enhanced/session-nr$"]["POST"] = setSessionNr;
    server.resource["^/api/hdr-enhanced/session-nr/remember$"]["POST"] = rememberSessionNr;
    server.resource["^/api/hdr-enhanced/components/([a-z0-9_.-]+)/maintenance$"]["POST"] = maintainImageEnhancementComponent;
    server.resource["^/api/webhook/config$"]["GET"] = getWebhookConfig;
    server.resource["^/api/webhook/config$"]["POST"] = saveWebhookConfig;
    server.resource["^/api/webhook/test$"]["POST"] = testWebhook;
#ifdef _WIN32
    server.resource["^/api/dualsense/config$"]["GET"] = getDualSenseConfig;
    server.resource["^/api/dualsense/config$"]["POST"] = saveDualSenseConfig;
#endif
    server.resource["^/api/configLocale$"]["GET"] = getLocale;
    server.resource["^/api/logout$"]["GET"] = handleLogout;
    server.resource["^/api/logout$"]["POST"] = handleLogout;
    server.resource["^/api/restart$"]["POST"] = restart;
    server.resource["^/api/restart$"]["GET"] = restart;
    server.resource["^/api/boom$"]["GET"] = boom;
    server.resource["^/api/reset-display-device-persistence$"]["POST"] = resetDisplayDevicePersistence;
    server.resource["^/api/microphone/test$"]["POST"] = testMicrophone;
    server.resource["^/api/microphone/status$"]["GET"] = getMicrophoneStatus;
#ifdef _WIN32
    server.resource["^/api/vdd/status$"]["GET"] = getVddStatus;
    server.resource["^/api/wintab/status$"]["GET"] = getWintabStatus;
    server.resource["^/api/wintab/install$"]["POST"] = installWintab;
    server.resource["^/api/wintab/uninstall$"]["POST"] = uninstallWintab;
    server.resource["^/api/presets/drawing$"]["GET"] = getDrawingMode;
    server.resource["^/api/presets/drawing$"]["POST"] = applyDrawingMode;
    server.resource["^/api/usb/link$"]["GET"] = getUsbLink;
    server.resource["^/api/usb/link$"]["POST"] = applyUsbLink;
    server.resource["^/api/usb/mode$"]["POST"] = switchUsbMode;
    server.resource["^/api/vulkan-hdr-bridge$"]["GET"] = getVulkanHdrBridgeStatus;
    server.resource["^/api/vulkan-hdr-bridge/validate$"]["POST"] = validateVulkanHdrBridge;
#endif
    server.resource["^/api/password$"]["POST"] = savePassword;
    server.resource["^/api/apps/([0-9]+)$"]["DELETE"] = deleteApp;
    server.resource["^/api/apps/batch-delete$"]["POST"] = batchDeleteApps;
    server.resource["^/api/clients/unpair-all$"]["POST"] = unpairAll;
    server.resource["^/api/clients/list$"]["GET"] = listClients;
    server.resource["^/api/clients/list$"]["POST"] = saveClients;
    server.resource["^/api/color-profiles$"]["GET"] = listColorProfiles;
    server.resource["^/api/clients/unpair$"]["POST"] = unpair;
    server.resource["^/api/clients/rename$"]["POST"] = renameClient;
    server.resource["^/api/apps/close$"]["POST"] = closeApp;
    server.resource["^/api/covers/upload$"]["POST"] = uploadCover;
    server.resource["^/api/apps/test-menu-cmd$"]["POST"] = testMenuCmd;
    server.resource["^/api/runtime/sessions$"]["GET"] = getRuntimeSessions;
    server.resource["^/api/runtime/sessions/stop$"]["POST"] = stopRuntimeSessions;
    server.resource["^/api/runtime/hdr$"]["GET"] = getRuntimeHdrStatus;
    server.resource["^/api/runtime/hdr-calibration$"]["GET"] = getRuntimeHdrCalibration;
    server.resource["^/api/runtime/bitrate$"]["GET"] = changeRuntimeBitrate;
    server.resource["^/api/perf/current$"]["GET"] = getPerfCurrent;
    server.resource["^/steam-api/.+$"]["GET"] = proxySteamApi;
    server.resource["^/steam-store/.+$"]["GET"] = proxySteamStore;
    server.resource["^/api/ai/config$"]["GET"] = getAiConfig;
    server.resource["^/api/ai/config$"]["POST"] = saveAiConfigEndpoint;
    server.resource["^/api/ai/models$"]["GET"] = proxyAiModels;
    server.resource["^/api/ai/chat/completions$"]["POST"] = proxyAiChat;
    server.resource["^/api/ai/chat/completions$"]["OPTIONS"] = handleAiCors;
    server.resource["^/api/v1/file-mapping/mappings$"]["GET"] = listFileMappings;
    server.resource["^/api/v1/file-mapping/mappings$"]["POST"] = createFileMapping;
    server.resource["^/api/v1/file-mapping/mappings/([A-Za-z0-9_\\-]{1,64})$"]["PATCH"] = updateFileMapping;
    server.resource["^/api/v1/file-mapping/mappings/([A-Za-z0-9_\\-]{1,64})$"]["DELETE"] = deleteFileMapping;
    server.resource["^/images/sunshine.ico$"]["GET"] = getFaviconImage;
    server.resource["^/images/logo-sunshine-256.png$"]["GET"] = getSunshineLogoImage;
    server.resource["^/images/logo-alkaidlab.png$"]["GET"] = getAlkaidLabLogoImage;
    server.resource["^/images/logo-natpierce.png$"]["GET"] = getNatPierceLogoImage;
    server.resource["^/boxart/.+$"]["GET"] = getBoxArt;

    // Clipboard sync routes are registered in a sibling module so the
    // existing 2700+ line confighttp doesn't grow further. They reuse our
    // basic-auth via the lambda below.
    clipboard_http::register_routes(server,
      [](clipboard_http::resp_https_t resp, clipboard_http::req_https_t req) {
        return authenticate(std::move(resp), std::move(req));
      });
    text_context::http::register_routes(server,
      [](text_context::http::resp_https_t resp, text_context::http::req_https_t req) {
        const auto address = net::addr_to_normalized_string(req->remote_endpoint().address());
        if (net::from_address(address) != net::PC) {
          resp->write(SimpleWeb::StatusCode::client_error_forbidden);
          return false;
        }
        return authenticate(std::move(resp), std::move(req));
      });
    tray_http::auth_fn tray_local_auth = [](tray_http::resp_https_t resp, tray_http::req_https_t req) {
      const auto address = net::addr_to_normalized_string(req->remote_endpoint().address());
      if (config::sunshine.username.empty() && net::from_address(address) == net::PC) {
        return authorize_browser_request(std::move(resp), std::move(req));
      }
      return authenticate(std::move(resp), std::move(req));
    };
    tray_http::register_routes(server, tray_local_auth, tray_local_auth);
    // Game Bar widget 通道:仅环回,凭证由模块内的 X-Sunshine-Token(widget_token)校验,
    // 不复用 basic-auth——widget 是本地 packaged app,没有浏览器语义。
    widget_http::register_routes(server, [](widget_http::resp_https_t resp, widget_http::req_https_t req) {
      const auto address = net::addr_to_normalized_string(req->remote_endpoint().address());
      if (net::from_address(address) != net::PC) {
        resp->write(SimpleWeb::StatusCode::client_error_forbidden);
        return false;
      }
      return true;
    });
    server.resource["^/assets\\/.+$"]["GET"] = getNodeModules;
    server.config.reuse_address = true;
    server.config.address = net::get_bind_address(address_family);
    server.config.port = port_https;
    // Use a small thread pool so that a slow request handler (proxy upstream,
    // file upload, etc.) doesn't block other web UI requests on the same
    // single-threaded io_service.
    server.config.thread_pool_size = 2;
    // Enforce the limit while Simple-Web-Server is buffering the request, before
    // individual handlers parse it. This still leaves headroom for the 10 MiB
    // base64 cover-upload endpoint.
    server.config.max_request_streambuf_size = 16 * 1024 * 1024;

    // A concrete bind address intentionally limits remote Sunshine traffic to
    // one interface. Keep an IPv4 loopback-only Web UI listener so the local
    // GUI/tray and Control Panel entry points remain available. The Panel
    // intentionally uses 127.0.0.1, including when the configured address is
    // IPv6.
    std::optional<https_server_t> loopback_server;
    if (!config::sunshine.bind_address.empty()) {
      boost::system::error_code bind_error;
      const auto configured_address = boost::asio::ip::make_address(config::sunshine.bind_address, bind_error);
      if (!bind_error && (configured_address.is_v6() || !configured_address.is_unspecified())) {
        const bool already_uses_panel_loopback = configured_address.is_v4() &&
          configured_address.to_v4() == boost::asio::ip::address_v4::loopback();
        if (!already_uses_panel_loopback) {
          loopback_server.emplace(config::nvhttp.cert, config::nvhttp.pkey);
          loopback_server->default_resource = server.default_resource;
          loopback_server->resource = server.resource;
          loopback_server->config.reuse_address = true;
          loopback_server->config.address = "127.0.0.1";
          loopback_server->config.port = port_https;
          loopback_server->config.thread_pool_size = server.config.thread_pool_size;
          loopback_server->config.max_request_streambuf_size = server.config.max_request_streambuf_size;
        }
      }
    }

    auto accept_and_run = [&](https_server_t *server,
                              const char *listener_name,
                              std::string listener_address,
                              bool required,
                              const std::shared_ptr<std::latch> &startup_latch,
                              const std::shared_ptr<std::atomic_bool> &startup_signaled) {
      const auto signal_startup = [&]() {
        if (startup_latch && startup_signaled && !startup_signaled->exchange(true)) {
          startup_latch->count_down();
        }
      };
      try {
        server->start([listener_name,
                       listener_address = std::move(listener_address),
                       startup_latch,
                       startup_signaled](unsigned short port) {
          if (startup_latch && startup_signaled && !startup_signaled->exchange(true)) {
            startup_latch->count_down();
          }
          BOOST_LOG(debug) << "Configuration UI listener ["sv << listener_name << "] ready at [https://"
                            << listener_address << ':' << port << "]"sv;
        });
      }
      catch (boost::system::system_error &err) {
        signal_startup();
        // It's possible the exception gets thrown after calling server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }
        if (!required) {
          BOOST_LOG(warning) << "Optional Configuration UI listener ["sv << listener_name
                             << "] could not start on ["sv << listener_address << ':' << port_https
                             << "]: "sv << err.what();
          return;
        }
        BOOST_LOG(fatal) << "Couldn't start Configuration HTTPS server on port ["sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
      catch (std::exception &err) {
        signal_startup();
        if (shutdown_event->peek()) {
          return;
        }
        if (!required) {
          BOOST_LOG(warning) << "Optional Configuration UI listener ["sv << listener_name
                             << "] failed on ["sv << listener_address << ':' << port_https
                             << "]: "sv << err.what();
          return;
        }
        BOOST_LOG(fatal) << "Configuration HTTPS server failed to start: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    const auto listener_host = [](const std::string &address) {
      boost::system::error_code error;
      const auto parsed = boost::asio::ip::make_address(address, error);
      return error ? address : net::addr_to_url_escaped_string(parsed);
    };

    std::thread tcp {
      accept_and_run,
      &server,
      "configured",
      listener_host(server.config.address),
      true,
      nullptr,
      nullptr
    };
    std::thread loopback_tcp;
    std::shared_ptr<std::latch> loopback_startup_latch;
    std::shared_ptr<std::atomic_bool> loopback_startup_signaled;
    if (loopback_server) {
      loopback_startup_latch = std::make_shared<std::latch>(1);
      loopback_startup_signaled = std::make_shared<std::atomic_bool>(false);
      loopback_tcp = std::thread {
        accept_and_run,
        &*loopback_server,
        "loopback",
        listener_host(loopback_server->config.address),
        false,
        loopback_startup_latch,
        loopback_startup_signaled
      };
      loopback_startup_latch->wait();
    }

    // Wait for any event
    shutdown_event->view();

    image_enhancement::api::shutdown();
    server.stop();
    if (loopback_server) {
      loopback_server->stop();
    }

    tcp.join();
    if (loopback_tcp.joinable()) {
      loopback_tcp.join();
    }
  }
}  // namespace confighttp
