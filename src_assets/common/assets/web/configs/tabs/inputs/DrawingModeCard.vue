<script setup>
/**
 * SuperSun drawing mode -- and everything that used to cost you throughput.
 *
 * This used to be a one-click preset, and that was a mistake. It rewrote twenty
 * settings behind a single button, so nothing about it was inspectable, and it
 * silently overwrote choices made elsewhere -- it kept switching nvenc_spatial_aq
 * back on after latency tuning had turned it off, which is how the conflict in
 * the first place went unnoticed for so long.
 *
 * So there is no "apply" any more. Every setting this card can reach is listed
 * with what it actually does, what the config holds right now, and the value we
 * would suggest. The user edits the rows they care about and saves just those.
 *
 * The 4K mode still looks backwards on a 2K panel and is still the point: the
 * panel is 2800x1752, but HEVC main/main10 is 4:2:0, so chroma is halved and at
 * the panel's PPI that shows up as soft hairlines and mushy UI text. Streaming
 * 3840x2400 and letting the client downscale is ~1.37x supersampling, which is
 * what actually buys the sharpness back -- raising the bitrate alone does not.
 *
 * The USB section below exists because three independent ceilings conspired to
 * cap the stream at roughly 200 Mbps even with the slider parked at 800 Mbps.
 * None of them describes a wired tether, so this panel lifts the host-side one
 * and stays conservative when no USB link is present.
 */
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiJson, apiPostJson } from '../../../utils/apiFetch.js'
import WintabPressureCard from './WintabPressureCard.vue'

const { t } = useI18n()

const loading = ref(false)
const message = ref('')
const isError = ref(false)

// Every option the host exposes, already carrying its label and help text.
const items = ref([])

// Which key is mid-write, so its row can show a spinner and block re-entry.
const savingKey = ref('')

const isSaving = computed(() => savingKey.value !== '')

// The host only reports groups it actually has rows for, so an unknown group
// id can never reach t() with a missing key.
// 'desktop' sits last on purpose: it is a host-desktop tweak rather than
// streaming quality, and only shows up when the host reports such a row.
const GROUP_ORDER = ['pen', 'video', 'display', 'desktop']
const GROUP_LABELS = {
  pen: 'config.drawing_group_pen',
  video: 'config.drawing_group_video',
  display: 'config.drawing_group_display',
  desktop: 'config.drawing_group_desktop',
}

const groups = computed(() => {
  const byGroup = new Map()
  for (const item of items.value) {
    if (!byGroup.has(item.group)) byGroup.set(item.group, [])
    byGroup.get(item.group).push(item)
  }
  return GROUP_ORDER
    .filter((g) => byGroup.has(g))
    .map((g) => ({ id: g, label: t(GROUP_LABELS[g]), items: byGroup.get(g) }))
})

function toggleLabel(on) {
  return on ? t('config.drawing_on') : t('config.drawing_off')
}

function displayValue(item) {
  if (item.control === 'toggle') return toggleLabel(item.value === 'enabled')
  return item.value
}

// --- USB 直连 ---
const usbLoading = ref(false)
const usbOperating = ref(false)
const usb = ref(null)
const usbMessage = ref('')

const usbPresent = computed(() => !!usb.value?.present)
// A USB RNDIS adapter reports a nominal 1 Gbit/s no matter what the cable
// actually negotiated, so the number on screen is decorative. Surfacing that
// keeps anyone from tuning bitrate against a figure that cannot be wrong.
const usbSpeedReliable = computed(() => usb.value?.speed_reliable !== false)
const usbMode = computed(() => usb.value?.mode || '')
const usbAdbFound = computed(() => !!usb.value?.adb_found)
const usbPresets = computed(() => (Array.isArray(usb.value?.presets) ? usb.value.presets : []))
// What the config actually holds right now, in Mbps.
const usbCurrentMbps = computed(() => Math.round((usb.value?.max_bitrate || 0) / 1000))
// The preset the user picked. null means "leave whatever is in the config alone",
// so the dropdown shows the real current value instead of always defaulting to
// the recommendation (which used to disagree with the config and confuse things).
const usbPresetMbps = ref(null)
const usbBitrateKbps = computed(() => {
  if (usbPresetMbps.value != null) return usbPresetMbps.value * 1000
  return usb.value?.max_bitrate || usb.value?.recommended_bitrate || 0
})

async function refresh() {
  loading.value = true
  message.value = ''
  isError.value = false
  try {
    const data = await apiJson('/api/presets/drawing')
    items.value = Array.isArray(data?.items) ? data.items : []
  } catch (e) {
    isError.value = true
    message.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

async function refreshUsb() {
  usbLoading.value = true
  try {
    usb.value = await apiJson('/api/usb/link')
  } catch (e) {
    usb.value = null
    usbMessage.value = e instanceof Error ? e.message : String(e)
  } finally {
    usbLoading.value = false
  }
}

// Persist one row the moment it changes. There is no staging form any more:
// a batch editor needs a save button, a dirty marker, a revert button and a
// "N unsaved" counter to all stay in sync, and the only thing a reader has to
// know is "the value under my cursor is already written".
async function commit(item, value) {
  if (value === item.value) return
  if (savingKey.value) return

  savingKey.value = item.key
  message.value = ''
  isError.value = false
  try {
    const data = await apiPostJson('/api/presets/drawing', { values: { [item.key]: value } })

    if (data?.status === false) {
      isError.value = true
      const rejected = Array.isArray(data?.rejected) ? data.rejected : []
      message.value = rejected.length
        ? rejected.map((r) => `${r.key}: ${r.reason}`).join('\n')
        : data?.message || t('config.drawing_save_failed')
      // Snap the control back: the write was refused, so what is on screen was
      // never true. Without this the row would keep showing a value the config
      // does not have.
      await refresh()
      await refreshUsb()
    } else {
      // Re-read rather than trusting the value we sent: the host normalises
      // (bool aliases, number formatting) and the row must show what landed.
      await refresh()
      await refreshUsb()
    }
  } catch (e) {
    isError.value = true
    message.value = e instanceof Error ? e.message : String(e)
    await refresh()
  } finally {
    savingKey.value = ''
  }
}

async function toggleUsbHighBandwidth(enable) {
  if (enable && !usbPresent.value) {
    usbMessage.value = t('config.drawing_usb_need_link')
    return
  }
  const confirmText = enable
    ? `${t('config.drawing_usb_confirm_on')}\n\n${t('config.drawing_usb_preset')}: ${usbBitrateKbps.value / 1000} Mbps`
    : t('config.drawing_usb_confirm_off')
  if (!confirm(confirmText)) return

  usbOperating.value = true
  usbMessage.value = ''
  try {
    // firewall: always. A tethered adapter is classified as an unidentified
    // (public) network by Windows, which silently drops every inbound Sunshine
    // port -- the tablet would pair fine and then never connect. Asking for the
    // rules unconditionally also cleans them up again when disabling.
    const data = await apiPostJson('/api/usb/link', {
      enable,
      firewall: true,
      bitrate: enable ? usbBitrateKbps.value : 0,
    })
    usbMessage.value = data?.message || t('config.drawing_usb_done')
    if (data?.firewall_error) {
      usbMessage.value += ` [${t('config.drawing_usb_firewall')}: ${data.firewall_error}]`
    }
    await refreshUsb()
  } catch (e) {
    usbMessage.value = e instanceof Error ? e.message : String(e)
  } finally {
    usbOperating.value = false
  }
}

async function switchUsbMode(mode) {
  if (!confirm(t('config.drawing_usb_mode_confirm') + '\n\n' + mode.toUpperCase())) return

  usbOperating.value = true
  usbMessage.value = ''
  try {
    const data = await apiPostJson('/api/usb/mode', { mode })
    usbMessage.value = data?.message || t('config.drawing_usb_mode_done')
    if (data?.output) console.log(data.output)
    await refreshUsb()
  } catch (e) {
    usbMessage.value = e instanceof Error ? e.message : String(e)
  } finally {
    usbOperating.value = false
  }
}

onMounted(async () => {
  await refresh()
  await refreshUsb()
})
</script>

<template>
  <div class="mb-3 accordion">
    <div class="accordion-item">
      <h2 class="accordion-header">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                data-bs-target="#drawing-mode-collapse">
          {{ $t('config.drawing_section') }}
        </button>
      </h2>
      <div id="drawing-mode-collapse" class="accordion-collapse collapse">
        <div class="accordion-body">
          <div class="form-text mb-2">{{ $t('config.drawing_desc') }}</div>

          <div v-if="loading" class="form-text">{{ $t('config.drawing_checking') }}</div>

          <template v-else>
            <!--
              One row per setting. Nothing is written until the user saves, and
              then only the rows they actually touched.
            -->
            <div v-for="group in groups" :key="group.id" class="drawing-group mb-3">
              <div class="drawing-group-title">{{ group.label }}</div>

              <div v-for="item in group.items" :key="item.key" class="drawing-option"
                   :class="{ 'drawing-option-saving': savingKey === item.key }">
                <div class="drawing-option-head">
                  <div class="drawing-option-text">
                    <span class="drawing-option-label">{{ item.label }}</span>
                    <code class="drawing-option-key">{{ item.key }}</code>
                  </div>

                  <div class="drawing-option-control">
                    <span v-if="savingKey === item.key" class="vmouse-spinner me-2"
                          :title="$t('config.drawing_saving')"></span>

                    <div v-if="item.control === 'toggle'" class="form-check form-switch mb-0">
                      <input class="form-check-input" type="checkbox" role="switch"
                             :id="'dopt-' + item.key"
                             :checked="item.value === 'enabled'"
                             :disabled="isSaving"
                             @change="commit(item, $event.target.checked ? 'enabled' : 'disabled')">
                    </div>

                    <select v-else-if="item.control === 'choice'"
                            class="form-select form-select-sm drawing-option-select"
                            :value="item.value"
                            :disabled="isSaving"
                            @change="commit(item, $event.target.value)">
                      <option v-for="(choice, i) in item.choices" :key="choice" :value="choice">
                        {{ choice }}{{ item.choice_notes?.[i] ? ' — ' + item.choice_notes[i] : '' }}
                      </option>
                    </select>

                    <!--
                      change, not input: writing on every keystroke would fire a
                      request for "0", "0." and "0.7" and the first two get rejected
                      by the host's range check. change waits for blur/Enter, which
                      is also when the value is complete.
                    -->
                    <input v-else-if="item.control === 'number'"
                           class="form-control form-control-sm"
                           type="number" style="width: 9rem"
                           :min="item.lo" :max="item.hi" :step="item.step || 1"
                           :value="item.value"
                           :disabled="isSaving"
                           @change="commit(item, $event.target.value)">

                    <input v-else class="form-control form-control-sm"
                           type="text" style="width: 12rem"
                           :value="item.value"
                           :disabled="isSaving"
                           @change="commit(item, $event.target.value)">
                  </div>
                </div>

                <div class="drawing-option-help">{{ item.help }}</div>

                <div class="drawing-option-foot">
                  <span class="drawing-option-current">
                    {{ $t('config.drawing_current') }}: <code>{{ displayValue(item) }}</code>
                  </span>
                  <span v-if="!item.is_default" class="drawing-option-differs">
                    {{ $t('config.drawing_differs') }}: <code>{{ item.recommended }}</code>
                  </span>
                </div>
              </div>
            </div>

            <!--
              高精度压感：原来这块在卡片最底部，和上面的设置项割裂开了。
              压感 DLL 装好后要重启绘图软件才生效，属于同一件事的一半，
              所以并到设置列表正下方 —— 改完设置、装完 DLL，一起重启。
            -->
            <div class="drawing-subsection mt-3">
              <div class="drawing-subsection-title">
                <i class="fas fa-arrow-down-up-across-line me-1"></i>
                <span>{{ $t('config.drawing_pressure_section') }}</span>
              </div>
              <div class="form-text mb-2">{{ $t('config.drawing_pressure_desc') }}</div>
              <WintabPressureCard />
            </div>

            <!--
              No save / revert / re-check bar here any more. Each row writes itself
              the moment it changes, and the rows above already show the live
              configured value, so there is nothing to batch up and nothing to
              put back.
            -->

            <!-- ---------------- USB 直连 / 高带宽 ---------------- -->
            <div class="drawing-subsection mt-3">
              <div class="drawing-subsection-title">
                <i class="fas fa-plug me-1"></i>
                <span>{{ $t('config.drawing_usb_section') }}</span>
                <span class="driver-badge" :class="usbPresent ? 'driver-badge-success' : 'driver-badge-warning'">
                  {{ usbPresent ? $t('config.drawing_usb_present') : $t('config.drawing_usb_absent') }}
                </span>
              </div>
              <div class="form-text mb-2">{{ $t('config.drawing_usb_desc') }}</div>

              <div v-if="usbLoading" class="form-text">{{ $t('config.drawing_checking') }}</div>

              <template v-else-if="usb">
                <div v-if="usb.present" class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_adapter') }}</span>
                  <code>{{ usb.adapter }}</code>
                </div>
                <div v-if="usb.present && usb.ip" class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_ip') }}</span>
                  <code>{{ usb.ip }}</code>
                </div>
                <div v-if="usb.present" class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_speed') }}</span>
                  <code>
                    {{ usb.link_speed_mbps }} Mbps
                    <em v-if="!usbSpeedReliable" class="drawing-warn">{{ $t('config.drawing_usb_speed_nominal') }}</em>
                  </code>
                </div>
                <div class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_recommended') }}</span>
                  <code>{{ usb.recommended_bitrate / 1000 }} Mbps</code>
                </div>
                <div v-if="usbPresets.length" class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_preset') }}</span>
                  <select v-model="usbPresetMbps" class="form-select form-select-sm w-auto">
                    <option :value="null">
                      {{ $t('config.drawing_usb_preset_current') }} {{ usbCurrentMbps }} Mbps
                    </option>
                    <option v-for="p in usbPresets" :key="p.label" :value="p.bitrate / 1000">
                      {{ p.bitrate / 1000 }} Mbps
                    </option>
                  </select>
                </div>
                <div v-if="usb.present && !usbSpeedReliable" class="vmouse-helper mt-2">
                  <i class="fas fa-circle-info me-1"></i>
                  <span>{{ $t('config.drawing_usb_speed_nominal_hint') }}</span>
                </div>
                <div class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_max_bitrate') }}</span>
                  <code :class="usbHighBandwidth ? 'drawing-ok' : 'drawing-warn'">
                    {{ usb.max_bitrate / 1000 }} Mbps
                  </code>
                </div>
                <div class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_fec') }}</span>
                  <code>{{ usb.fec_percentage }} %</code>
                </div>

                <div class="vmouse-panel-body px-0 mt-2">
                  <button v-if="!usbHighBandwidth" class="vmouse-action-btn vmouse-install-btn"
                          @click="toggleUsbHighBandwidth(true)" :disabled="usbOperating || !usbPresent">
                    <span v-if="usbOperating" class="vmouse-spinner"></span>
                    <i v-else class="fas fa-gauge-high"></i>
                    <span>{{ $t('config.drawing_usb_enable') }}</span>
                  </button>
                  <button v-else class="vmouse-action-btn vmouse-uninstall-btn"
                          @click="toggleUsbHighBandwidth(false)" :disabled="usbOperating">
                    <span v-if="usbOperating" class="vmouse-spinner"></span>
                    <i v-else class="fas fa-lock"></i>
                    <span>{{ $t('config.drawing_usb_disable') }}</span>
                  </button>
                </div>

                <!-- 协议切换：NCM 省 CPU 但小包延迟未必更好，所以是"可试"而不是"推荐" -->
                <div v-if="usb.present && usbMode" class="drawing-kv">
                  <span>{{ $t('config.drawing_usb_mode') }}</span>
                  <code>{{ usbMode.toUpperCase() }}</code>
                </div>
                <div class="vmouse-panel-body px-0 mt-2">
                  <button class="vmouse-action-btn vmouse-install-btn"
                          :disabled="usbOperating || !usbAdbFound || usbMode === 'ncm'"
                          @click="switchUsbMode('ncm')">
                    <span v-if="usbOperating" class="vmouse-spinner"></span>
                    <i v-else class="fas fa-right-left"></i>
                    <span>{{ $t('config.drawing_usb_mode_ncm') }}</span>
                  </button>
                  <button class="vmouse-action-btn vmouse-uninstall-btn"
                          :disabled="usbOperating || !usbAdbFound || usbMode === 'rndis'"
                          @click="switchUsbMode('rndis')">
                    <span v-if="usbOperating" class="vmouse-spinner"></span>
                    <i v-else class="fas fa-rotate-left"></i>
                    <span>{{ $t('config.drawing_usb_mode_rndis') }}</span>
                  </button>
                </div>
                <div v-if="!usbAdbFound" class="vmouse-helper mt-2">
                  <i class="fas fa-triangle-exclamation me-1"></i>
                  <span>{{ $t('config.drawing_usb_no_adb') }}</span>
                </div>

                <div v-if="usb.hint" class="vmouse-helper mt-2">
                  <i class="fas fa-info-circle me-1"></i>
                  <span>{{ usb.hint }}</span>
                </div>

                <div class="vmouse-helper mt-2">
                  <i class="fas fa-triangle-exclamation me-1"></i>
                  <span>{{ $t('config.drawing_usb_client_hint') }}</span>
                </div>
              </template>

              <div v-if="usbMessage" class="vmouse-helper mt-2">
                <i class="fas fa-check-circle"></i>
                <span class="ms-1">{{ usbMessage }}</span>
              </div>
            </div>

            <div class="vmouse-helper mt-3">
              <i class="fas fa-info-circle me-1"></i>
              <span>{{ $t('config.drawing_hint') }}</span>
            </div>
          </template>

          <div v-if="message" class="vmouse-helper mt-2" :class="{ 'wintab-error': isError }">
            <i class="fas" :class="isError ? 'fa-exclamation-triangle' : 'fa-check-circle'"></i>
            <span class="ms-1">{{ message }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.drawing-status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.drawing-kv {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.25rem 0;
  font-size: 0.85rem;
}

.drawing-kv code {
  font-family: var(--ui-font-mono, monospace);
  font-size: 0.78rem;
}

.drawing-ok {
  color: var(--ui-success-text, #2f9e63);
}

.drawing-warn {
  color: var(--ui-warning-text, #b8860b);
}

.drawing-subsection {
  border-top: 1px solid var(--ui-border-subtle, rgba(128, 128, 128, 0.25));
  padding-top: 0.75rem;
}

.drawing-subsection-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  font-weight: 600;
  margin-bottom: 0.35rem;
}

.drawing-subsection-title :deep(.accordion) {
  margin-bottom: 0 !important;
}

.drawing-detail-title {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--ui-text-muted);
  margin-top: 0.5rem;
}

.drawing-diff {
  font-family: var(--ui-font-mono, monospace);
  font-size: 0.72rem;
  color: var(--ui-text-muted);
  padding-left: 1.1rem;
  margin: 0.25rem 0;
  word-break: break-all;
}

.wintab-error {
  background: var(--ui-danger-soft);
  border-color: var(--ui-danger-border);
  color: var(--ui-danger-text);
}

/* ---- per-setting editor rows ---------------------------------------- */
.drawing-group-title {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--ui-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 0.5rem;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid var(--ui-border-subtle);
}

.drawing-option {
  border: 1px solid var(--ui-border-subtle);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
  margin-bottom: 0.5rem;
  background: var(--ui-bg-subtle);
}

/* The row being written right now. Replaces the old "dirty" highlight: there
   is no longer a state where a row holds an unsaved edit. */
.drawing-option-saving {
  border-color: var(--accent);
  background: var(--ui-accent-soft, transparent);
}

.drawing-option-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
}

.drawing-option-text {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.drawing-option-label {
  font-weight: 500;
  color: var(--ui-text-primary);
}

.drawing-option-key {
  font-size: 0.75rem;
  color: var(--ui-text-muted);
  word-break: break-all;
}

.drawing-option-control {
  flex-shrink: 0;
}

/*
  Choice options carry a per-value explanation ("4 — 去噪更强，但细节会被抹平"),
  so the dropdown needs room. Left to the default `w-auto` the select sizes to
  the longest option and the labels squeeze the key column to nothing; capping it
  lets the select scroll instead, and on narrow screens it drops below the label.
*/
.drawing-option-select {
  min-width: 15rem;
  max-width: 26rem;
}

@media (max-width: 900px) {
  .drawing-option-select {
    min-width: 0;
    width: 100%;
    margin-top: 0.4rem;
  }

  .drawing-option-head {
    flex-direction: column;
  }
}

.drawing-option-help {
  font-size: 0.85rem;
  color: var(--ui-text-muted);
  margin-top: 0.4rem;
  line-height: 1.5;
}

.drawing-option-foot {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 0.45rem;
  font-size: 0.8rem;
  color: var(--ui-text-muted);
}

.drawing-option-differs code {
  color: var(--ui-warning-text, var(--ui-text-muted));
}

</style>
