<script setup>
/**
 * High-pressure-resolution Wintab deployment.
 *
 * Windows clamps pen pressure injected through the pointer stack to 1024 steps.
 * Sunshine additionally publishes the raw pen state into shared memory, and our
 * own Wintab32.dll reads it there with a 4096 pressure axis. Because Windows
 * resolves Wintab32.dll from the application directory before System32,
 * "installing" is just a file copy next to the drawing app's exe -- which also
 * means only that one app is affected and removing the file reverts everything.
 *
 * Unlike the vmouse / ViGEm panels this one talks to the REST API, so it works
 * in a plain browser and not only inside the Tauri desktop shell.
 */
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiJson, apiPostJson } from '../../../utils/apiFetch.js'

const { t } = useI18n()

const loading = ref(false)
const operating = ref(false)
const message = ref('')
const isError = ref(false)
const bundled = ref(false)
const bundledPath = ref('')
const targets = ref([])
const manualDir = ref('')

const hasTargets = computed(() => targets.value.length > 0)

async function refresh() {
  loading.value = true
  message.value = ''
  isError.value = false
  try {
    const data = await apiJson('/api/wintab/status')
    bundled.value = !!data?.bundled
    bundledPath.value = data?.bundled_path || ''
    targets.value = Array.isArray(data?.targets) ? data.targets : []
  } catch (e) {
    isError.value = true
    message.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

function dotClass(target) {
  if (!target.installed) return 'dot-inactive'
  if (target.match) return 'dot-active'
  return 'dot-warning'
}

function statusLabel(target) {
  if (!target.installed) return t('config.wintab_status_not_installed')
  if (target.match) return t('config.wintab_status_installed')
  return t('config.wintab_status_outdated')
}

async function runOp(dir, install) {
  if (!dir) return
  if (install && !confirm(t('config.wintab_confirm_install'))) return
  if (!install && !confirm(t('config.wintab_confirm_uninstall'))) return

  operating.value = true
  message.value = ''
  isError.value = false
  try {
    const data = await apiPostJson(install ? '/api/wintab/install' : '/api/wintab/uninstall', { dir })
    message.value = data?.message || t('config.wintab_done')
    isError.value = data?.status === false
    await refresh()
  } catch (e) {
    isError.value = true
    message.value = e instanceof Error ? e.message : String(e)
  } finally {
    operating.value = false
  }
}

onMounted(refresh)
</script>

<template>
  <div class="mb-3 accordion">
    <div class="accordion-item">
      <h2 class="accordion-header">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                data-bs-target="#wintab-pressure-collapse">
          {{ $t('config.wintab_section') }}
        </button>
      </h2>
      <div id="wintab-pressure-collapse" class="accordion-collapse collapse">
        <div class="accordion-body">
          <div class="form-text mb-2">{{ $t('config.wintab_desc') }}</div>

          <div v-if="!bundled" class="vmouse-helper mb-2">
            <i class="fas fa-info-circle me-1"></i>
            <span>{{ $t('config.wintab_bundled_missing') }}</span>
          </div>

          <div v-if="loading" class="form-text">{{ $t('config.wintab_checking') }}</div>

          <template v-else>
            <div v-if="!hasTargets" class="form-text mb-2">{{ $t('config.wintab_no_targets') }}</div>

            <div v-for="target in targets" :key="target.dir" class="vmouse-panel mb-2">
              <div class="vmouse-panel-header">
                <div class="vmouse-status-indicator">
                  <span class="vmouse-dot" :class="dotClass(target)"></span>
                  <span class="vmouse-status-label">
                    {{ target.name }} &mdash; {{ statusLabel(target) }}
                  </span>
                </div>
                <span v-if="target.running" class="driver-badge driver-badge-warning">
                  {{ $t('config.wintab_running') }}
                </span>
              </div>
              <div class="wintab-dir">{{ target.dir }}</div>
              <div class="vmouse-panel-body">
                <button v-if="!target.installed || !target.match" class="vmouse-action-btn vmouse-install-btn"
                        @click="runOp(target.dir, true)" :disabled="operating">
                  <span v-if="operating" class="vmouse-spinner"></span>
                  <i v-else class="fas fa-download"></i>
                  <span>{{ target.installed ? $t('config.wintab_update') : $t('config.wintab_install') }}</span>
                </button>
                <button v-if="target.installed" class="vmouse-action-btn vmouse-uninstall-btn"
                        @click="runOp(target.dir, false)" :disabled="operating">
                  <span v-if="operating" class="vmouse-spinner"></span>
                  <i v-else class="fas fa-trash-alt"></i>
                  <span>{{ $t('config.wintab_uninstall') }}</span>
                </button>
              </div>
            </div>

            <hr>

            <label for="wintab_manual_dir" class="form-label">{{ $t('config.wintab_manual_dir') }}</label>
            <input id="wintab_manual_dir" type="text" class="form-control"
                   :placeholder="$t('config.wintab_manual_dir_hint')" v-model="manualDir">
            <div class="form-text">{{ $t('config.wintab_manual_dir_desc') }}</div>
            <div class="vmouse-panel-body px-0 mt-2">
              <button class="vmouse-action-btn vmouse-install-btn" @click="runOp(manualDir, true)"
                      :disabled="operating || !manualDir">
                <i class="fas fa-download"></i>
                <span>{{ $t('config.wintab_install') }}</span>
              </button>
              <button class="vmouse-action-btn vmouse-uninstall-btn" @click="runOp(manualDir, false)"
                      :disabled="operating || !manualDir">
                <i class="fas fa-trash-alt"></i>
                <span>{{ $t('config.wintab_uninstall') }}</span>
              </button>
            </div>
          </template>

          <div v-if="message" class="vmouse-helper mt-2" :class="{ 'wintab-error': isError }">
            <i class="fas" :class="isError ? 'fa-exclamation-triangle' : 'fa-check-circle'" ></i>
            <span class="ms-1">{{ message }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.wintab-dir {
  padding: 0.4rem 0.85rem;
  font-family: var(--ui-font-mono, monospace);
  font-size: 0.72rem;
  color: var(--ui-text-muted);
  word-break: break-all;
}

.wintab-error {
  background: var(--ui-danger-soft);
  border-color: var(--ui-danger-border);
  color: var(--ui-danger-text);
}
</style>
