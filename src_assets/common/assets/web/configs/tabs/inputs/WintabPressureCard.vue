<script setup>
/**
 * High-pressure-resolution Wintab deployment.
 *
 * Windows clamps pen pressure injected through the pointer stack to 1024 steps.
 * Sunshine additionally publishes the raw pen state into shared memory, and our
 * own Wintab32.dll reads it there with a full-resolution pressure axis. The
 * axis ceiling and the gain are both read per call, so the card can change them
 * under a running app -- though whatever the app cached at startup is its own
 * business, which is why the range notes say a restart is needed.
 * Because Windows
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
// Kept as a computed rather than inline in the template: a bare "<" inside a
// text interpolation is ambiguous to the HTML parser.
const hasSavedGain = computed(() => storedUserMax.value > 0 && storedUserMax.value < 1)

// The canvas only ever sees the wire's normalised 0..1, so a "level count" is
// just that value multiplied by whatever range the user declared. This is why
// a device whose real axis is 4096 still reads 100% with the field set to 8192:
// reaching the top only means the hardware hit ITS OWN full scale, it says
// nothing about whether the declared range is correct. Only the digitizer's
// descriptor knows that, and it never crosses the wire.
const deviceMaxSafe = computed(() => {
  const n = Math.round(Number(deviceMax.value))
  return Number.isFinite(n) && n > 0 ? n : 4096
})
const liveCount = computed(() => Math.round(live.value * deviceMaxSafe.value))
const peakCount = computed(() => Math.round(peak.value * deviceMaxSafe.value))

// Editing only the range must stay saveable: otherwise the user has to press
// the canvas again just to write a number that was never measured here.
const dirtyDevice = computed(() => deviceMaxSafe.value !== storedDeviceMax.value)
const canSave = computed(() => !operating.value && (peak.value >= 0.05 || dirtyDevice.value))

const gainHint = computed(() => {
  if (dirtyDevice.value) return t('config.wintab_calib_dirty')
  return hasSavedGain.value ? t('config.wintab_calib_saved_gain') : t('config.wintab_calib_not_saved')
})

// ---------------------------------------------------------------- calibration
// deviceMax is the digitizer's real range: what the WinTab axis advertises.
// userMax is the highest pressure THIS user can reach, used as a gain so a
// light touch still reaches full brush size. Neither is guessed on the fly --
// the wire only carries 0..1, so the level count has to be entered or reported.
const deviceMax = ref(4096)
const presetDeviceMax = ref(4096)
const storedDeviceMax = ref(4096)
const storedUserMax = ref(1.0)
const limits = ref({ min: 256, max: 65536 })
const calibrating = ref(false)
const peak = ref(0)
const live = ref(0)
const samples = ref(0)
const usedPen = ref(false)
const canvasRef = ref(null)
let drawing = false

async function loadPressure() {
  try {
    const data = await apiJson('/api/wintab/pressure')
    if (data?.status === false) return
    deviceMax.value = data?.device_max ?? deviceMax.value
    storedDeviceMax.value = data?.device_max ?? storedDeviceMax.value
    presetDeviceMax.value = data?.default_device_max ?? presetDeviceMax.value
    storedUserMax.value = data?.user_max ?? 1.0
    if (data?.limits) limits.value = data.limits
    peak.value = storedUserMax.value < 1 ? storedUserMax.value : 0
    redraw()
  } catch {
    /* the card still works offline; the POST will surface the error */
  }
}

function toggleCalibration() {
  calibrating.value = !calibrating.value
  if (calibrating.value) {
    peak.value = 0
    live.value = 0
    samples.value = 0
    usedPen.value = false
  }
  redraw()
}

function pressureFrom(e) {
  // Chrome reports 0.5 for a mouse button press and for pens without pressure
  // support. That is not a measurement, so it is flagged in the UI instead of
  // being silently folded into the peak.
  if (e.pointerType === 'pen') usedPen.value = true
  const p = Number(e.pressure)
  return Number.isFinite(p) ? Math.max(0, Math.min(1, p)) : 0
}

function sample(e) {
  const p = pressureFrom(e)
  live.value = p
  if (p > peak.value) peak.value = p
  samples.value += 1
  redraw()
}

function onPointerDown(e) {
  if (!calibrating.value) return
  e.preventDefault()
  drawing = true
  try { e.target.setPointerCapture(e.pointerId) } catch { /* not fatal */ }
  sample(e)
}

function onPointerMove(e) {
  if (!drawing || !calibrating.value) return
  e.preventDefault()
  sample(e)
}

function onPointerUp() {
  drawing = false
}

function redraw() {
  const c = canvasRef.value
  if (!c) return
  const dpr = window.devicePixelRatio || 1
  const w = c.clientWidth || 480
  const h = c.clientHeight || 110
  const pw = Math.round(w * dpr)
  const ph = Math.round(h * dpr)
  if (c.width !== pw || c.height !== ph) {
    c.width = pw
    c.height = ph
  }
  const g = c.getContext('2d')
  if (!g) return
  g.setTransform(dpr, 0, 0, dpr, 0, 0)
  g.fillStyle = '#f1f3f5'
  g.fillRect(0, 0, w, h)

  // Live pressure as a growing bar from the bottom.
  g.fillStyle = '#3b82f6'
  g.fillRect(0, h - h * live.value, w, h * live.value)

  // Peak as a marker the user is trying to push to the right edge.
  if (peak.value > 0) {
    const x = Math.min(w - 2, w * peak.value)
    g.strokeStyle = '#f59e0b'
    g.lineWidth = 2
    g.beginPath()
    g.moveTo(x, 0)
    g.lineTo(x, h)
    g.stroke()
  }

  g.fillStyle = '#495057'
  g.font = '600 13px system-ui, sans-serif'
  g.fillText(`${liveCount.value} / ${deviceMaxSafe.value}`, 8, 18)
  if (peak.value > 0) {
    g.font = '12px system-ui, sans-serif'
    g.fillText(`${t('config.wintab_calib_peak')} ${peakCount.value} / ${deviceMaxSafe.value}  (${(peak.value * 100).toFixed(1)}%)`, 8, 36)
  }
}

async function postPressure(payload) {
  operating.value = true
  message.value = ''
  isError.value = false
  try {
    const data = await apiPostJson('/api/wintab/pressure', payload)
    message.value = data?.message || t('config.wintab_done')
    isError.value = data?.status === false
    await loadPressure()
  } catch (e) {
    isError.value = true
    message.value = e instanceof Error ? e.message : String(e)
  } finally {
    operating.value = false
  }
}

async function savePressure() {
  // A peak below 5% is almost certainly "the user never actually pressed", so
  // refuse rather than writing a gain that would saturate the pen instantly.
  // The exception is a range-only edit: keep whatever gain is already stored.
  const measured = peak.value >= 0.05
  if (!measured && !dirtyDevice.value) {
    isError.value = true
    message.value = t('config.wintab_calib_too_low')
    return
  }
  await postPressure({
    device_max: deviceMaxSafe.value,
    user_max: measured ? Number(peak.value.toFixed(4)) : storedUserMax.value,
  })
}

async function clearCalibration() {
  peak.value = 0
  live.value = 0
  await postPressure({ device_max: deviceMaxSafe.value, user_max: 1.0 })
}

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

onMounted(() => {
  refresh()
  loadPressure()
})
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

          <hr>

          <div class="wintab-calib">
            <div class="wintab-calib-title">{{ $t('config.wintab_calib_section') }}</div>
            <div class="form-text mb-2">{{ $t('config.wintab_calib_desc') }}</div>

            <div class="row g-2 align-items-start mb-2">
              <div class="col-sm-6">
                <label for="wintab_device_max" class="form-label">
                  {{ $t('config.wintab_calib_device_max') }}
                </label>
                <input id="wintab_device_max" type="number" class="form-control"
                       :min="limits.min" :max="limits.max" step="1" v-model.number="deviceMax">
                <div class="form-text">
                  {{ $t('config.wintab_calib_device_max_hint') }}
                  <span class="wintab-calib-link" @click="deviceMax = presetDeviceMax">
                    ({{ presetDeviceMax }})
                  </span>
                </div>
                <div class="form-text wintab-calib-note">
                  <i class="fas fa-arrows-rotate me-1"></i>
                  <span>{{ $t('config.wintab_calib_device_max_restart') }}</span>
                </div>
                <div class="form-text wintab-calib-note">
                  <i class="fas fa-circle-info me-1"></i>
                  <span>{{ $t('config.wintab_calib_device_max_note') }}</span>
                </div>
                <div v-if="deviceMaxSafe !== presetDeviceMax" class="form-text wintab-calib-warn">
                  <i class="fas fa-triangle-exclamation me-1"></i>
                  <span>{{ $t('config.wintab_calib_device_max_custom', { preset: presetDeviceMax }) }}</span>
                </div>
              </div>
              <div class="col-sm-6">
                <div class="form-label">{{ $t('config.wintab_calib_user_max') }}</div>
                <div class="wintab-calib-readout">
                  <span class="wintab-calib-live">
                    {{ $t('config.wintab_calib_live') }} {{ liveCount }} / {{ deviceMaxSafe }}
                  </span>
                  <span class="wintab-calib-samples">
                    {{ samples }} {{ $t('config.wintab_calib_samples') }}
                  </span>
                </div>
                <div class="wintab-calib-readout">
                  <span class="wintab-calib-peak">
                    {{ $t('config.wintab_calib_peak') }} {{ peakCount }} / {{ deviceMaxSafe }}
                  </span>
                  <span class="wintab-calib-pct">{{ (peak * 100).toFixed(1) }}%</span>
                </div>
                <div class="form-text">
                  {{ gainHint }}
                </div>
                <div class="form-text wintab-calib-note">
                  <i class="fas fa-bolt me-1"></i>
                  <span>{{ $t('config.wintab_calib_user_max_live') }}</span>
                </div>
              </div>
            </div>

            <canvas ref="canvasRef" class="wintab-canvas"
                    @pointerdown="onPointerDown" @pointermove="onPointerMove"
                    @pointerup="onPointerUp" @pointercancel="onPointerUp"
                    @pointerleave="onPointerUp"></canvas>

            <div class="form-text mb-2">
              {{ calibrating ? $t('config.wintab_calib_press_hint') : $t('config.wintab_calib_idle_hint') }}
              <span v-if="calibrating && !usedPen" class="wintab-calib-warn">
                {{ $t('config.wintab_calib_not_pen') }}
              </span>
            </div>

            <div class="vmouse-panel-body px-0">
              <button class="vmouse-action-btn vmouse-install-btn" @click="toggleCalibration">
                <i class="fas" :class="calibrating ? 'fa-stop' : 'fa-pen'"></i>
                <span>{{ calibrating ? $t('config.wintab_calib_stop') : $t('config.wintab_calib_start') }}</span>
              </button>
              <button class="vmouse-action-btn vmouse-install-btn" @click="savePressure"
                      :disabled="!canSave">
                <span v-if="operating" class="vmouse-spinner"></span>
                <i v-else class="fas fa-save"></i>
                <span>{{ $t('config.wintab_calib_apply') }}</span>
              </button>
              <button class="vmouse-action-btn vmouse-uninstall-btn" @click="clearCalibration" :disabled="operating">
                <i class="fas fa-undo"></i>
                <span>{{ $t('config.wintab_calib_clear') }}</span>
              </button>
            </div>
          </div>

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

.wintab-calib-title {
  font-weight: 600;
  margin-bottom: 0.25rem;
}

/* touch-action: none is load-bearing. Without it the browser treats a pen drag
   as a scroll gesture and never delivers pointermove, so the canvas would only
   ever see the initial press. */
.wintab-canvas {
  display: block;
  width: 100%;
  height: 110px;
  border: 1px solid var(--ui-border, #dee2e6);
  border-radius: 0.375rem;
  touch-action: none;
  cursor: crosshair;
  user-select: none;
}

.wintab-calib-readout {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 0.5rem;
  font-family: var(--ui-font-mono, monospace);
  font-size: 0.95rem;
  line-height: 1.3;
}

.wintab-calib-peak {
  font-weight: 600;
}

.wintab-calib-pct {
  font-size: 0.78rem;
  color: var(--ui-text-muted);
}

.wintab-calib-samples {
  font-size: 0.72rem;
  color: var(--ui-text-muted);
}

.wintab-calib-note {
  margin-top: 0.25rem;
  color: var(--ui-text-muted);
}

.wintab-calib-link {
  cursor: pointer;
  text-decoration: underline;
}

.wintab-calib-warn {
  display: block;
  color: #b45309;
}
</style>
