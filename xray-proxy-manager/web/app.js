const state = {
  payload: null,
  settingsInitialized: false,
  filterSaveTimer: null,
  restartChanges: null,
  logsOpen: false,
  logsTimer: null,
  logsLines: [],
  logsTotal: 0,
  logSearchQuery: '',
  logSearchIndex: -1,
  logWrapDisabled: true,
  savedAutoChecker: null,
  savedSubscription: null,
  changelogOpen: false,
  releaseNotes: [],
};

const $ = (id) => document.getElementById(id);
const api = (path) => new URL(path.replace(/^\//, ''), window.location.href.endsWith('/') ? window.location.href : `${window.location.href}/`).toString();

let hapticMessageId = 1;
let lastHapticAt = 0;

function accessibleContexts() {
  const contexts = [];
  for (const candidate of [window, window.parent, window.top]) {
    try {
      if (candidate && !contexts.includes(candidate)) contexts.push(candidate);
    } catch (_error) { /* cross-origin parent */ }
  }
  return contexts;
}

function postNativeHaptic(context, message) {
  try {
    if (context.externalAppV2?.postMessage) {
      context.externalAppV2.postMessage(message);
      return true;
    }
    if (context.externalApp?.externalBus) {
      context.externalApp.externalBus(message);
      return true;
    }
    if (context.webkit?.messageHandlers?.externalBus?.postMessage) {
      context.webkit.messageHandlers.externalBus.postMessage(message);
      return true;
    }
  } catch (_error) { /* unavailable or protected native bridge */ }
  return false;
}

function dispatchFrontendHaptic(context, hapticType) {
  try {
    context.dispatchEvent(new context.CustomEvent('haptic', {
      bubbles: false,
      composed: false,
      detail: hapticType,
    }));
    return true;
  } catch (_error) {
    return false;
  }
}

function sendHomeAssistantHaptic(hapticType = 'light') {
  const message = JSON.stringify({
    id: hapticMessageId++,
    type: 'haptic',
    payload: { hapticType },
  });
  const contexts = accessibleContexts().reverse();

  for (const context of contexts) {
    if (postNativeHaptic(context, message)) return 'native';
  }
  for (const context of contexts) {
    if (dispatchFrontendHaptic(context, hapticType)) return 'frontend';
  }
  return 'none';
}

function hapticFeedback(hapticType = 'light') {
  const delivery = sendHomeAssistantHaptic(hapticType);
  if (delivery !== 'native' && typeof navigator.vibrate === 'function') {
    try { navigator.vibrate(18); } catch (_error) { /* unsupported browser */ }
  }
}

function hapticOnce(hapticType = 'light') {
  const now = Date.now();
  if (now - lastHapticAt < 90) return;
  lastHapticAt = now;
  hapticFeedback(hapticType);
}

function interactiveControlFromEvent(event) {
  const target = event.target instanceof Element ? event.target : null;
  const control = target?.closest('button, .switch, .check-control');
  if (!control) return null;
  const disabled = control.matches('button:disabled') || Boolean(control.querySelector?.('input:disabled'));
  return disabled ? null : control;
}

document.addEventListener('pointerdown', (event) => {
  if (!interactiveControlFromEvent(event)) return;
  hapticOnce('light');
}, { capture: true, passive: true });

if (!window.PointerEvent) {
  document.addEventListener('touchstart', (event) => {
    if (interactiveControlFromEvent(event)) hapticOnce('light');
  }, { capture: true, passive: true });
}

document.addEventListener('keydown', (event) => {
  if (!['Enter', ' '].includes(event.key)) return;
  if (interactiveControlFromEvent(event)) hapticOnce('light');
}, { capture: true });

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}

function formatDateTime(timestamp) {
  if (!timestamp) return 'нет данных';
  return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'medium' })
    .format(new Date(timestamp * 1000));
}

function formatRelative(timestamp) {
  if (!timestamp) return 'нет данных';
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - timestamp));
  if (seconds < 10) return 'только что';
  if (seconds < 60) return `${seconds} сек. назад`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} мин. назад`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч. назад`;
  const days = Math.floor(hours / 24);
  return `${days} дн. назад`;
}

function protocolMeta(item) {
  const endpoint = item.server ? `${item.server}${item.port ? `:${item.port}` : ''}` : 'адрес скрыт в конфигурации';
  return `${endpoint} · ${item.outbound_tag}`;
}

function latencyRank(item) {
  const latency = item.latency;
  if (latency?.status === 'ok' && Number.isFinite(latency.latency_ms)) return latency.latency_ms;
  return Number.POSITIVE_INFINITY;
}

function currentUiSettings() {
  return {
    sort: $('sortSelect').value,
    protocol_filter: $('protocolFilter').value,
    max_ping_ms: Number.parseInt($('maxPing').value || '0', 10) || 0,
    hide_unavailable: $('hideUnavailable').checked,
  };
}

function normalizeCountryCodes(value) {
  const seen = new Set();
  return String(value || '')
    .toUpperCase()
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter((item) => /^[A-Z]{2}$/.test(item) && !seen.has(item) && seen.add(item))
    .join(',');
}

function autoCheckerFormValues() {
  return {
    auto_checker_enabled: $('autoCheckerEnabled').checked,
    auto_switch_best_enabled: $('autoSwitchBestEnabled').checked,
    auto_check_interval_seconds: Number.parseInt($('autoCheckInterval').value, 10),
    auto_check_failures: Number.parseInt($('autoCheckFailures').value, 10),
    auto_switch_excluded_countries: normalizeCountryCodes($('autoSwitchExcludedCountries').value),
    auto_switch_min_ping_delta_ms: Number.parseInt($('autoSwitchMinPingDelta').value, 10),
  };
}

function subscriptionFormValues() {
  return {
    subscription_url: $('subscriptionUrl').value.trim(),
    update_interval_hours: Number.parseInt($('subscriptionInterval').value, 10),
  };
}

function sameSettings(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function updateSaveButtons() {
  const autoDirty = state.savedAutoChecker && !sameSettings(autoCheckerFormValues(), state.savedAutoChecker);
  const subscriptionDirty = state.savedSubscription && !sameSettings(subscriptionFormValues(), state.savedSubscription);
  $('saveAutoChecker').classList.toggle('dirty', Boolean(autoDirty));
  $('saveSubscription').classList.toggle('dirty', Boolean(subscriptionDirty));
}

function sortedAndFilteredCandidates(items) {
  const settings = currentUiSettings();
  const protocol = settings.protocol_filter;
  const maxPing = settings.max_ping_ms;
  const filtered = items.filter((item) => {
    if (protocol !== 'all' && item.protocol !== protocol) return false;
    if (settings.hide_unavailable && item.latency?.status === 'error') return false;
    if (maxPing > 0 && item.latency?.status === 'ok' && item.latency.latency_ms > maxPing) return false;
    return true;
  });

  const [field, direction] = settings.sort.split('-');
  const factor = direction === 'desc' ? -1 : 1;
  filtered.sort((a, b) => {
    if (field === 'ping') {
      const av = latencyRank(a); const bv = latencyRank(b);
      const aMissing = !Number.isFinite(av); const bMissing = !Number.isFinite(bv);
      if (aMissing !== bMissing) return aMissing ? 1 : -1;
      if (!aMissing && av !== bv) return (av - bv) * factor;
    }
    if (field === 'protocol') {
      const protocolCompare = a.protocol.localeCompare(b.protocol, 'ru', { sensitivity: 'base' });
      if (protocolCompare !== 0) return protocolCompare * factor;
    }
    return a.name.localeCompare(b.name, 'ru', { sensitivity: 'base' }) * factor;
  });
  return filtered;
}

function pingMarkup(item) {
  const latency = item.latency;
  if (!latency) return '<span class="ping">не проверен</span>';
  if (latency.status === 'ok') {
    return `<span class="ping ok" title="${escapeHtml(formatDateTime(latency.checked_at))}">${latency.latency_ms} мс</span>`;
  }
  return `<span class="ping bad" title="${escapeHtml(latency.error || 'Ошибка')}">недоступен</span>`;
}

function renderProtocols(protocols) {
  const select = $('protocolFilter');
  const current = select.value || 'all';
  const values = ['all', ...(protocols || [])];
  select.innerHTML = values.map((value) => (
    `<option value="${escapeHtml(value)}">${value === 'all' ? 'Все протоколы' : escapeHtml(value)}</option>`
  )).join('');
  select.value = values.includes(current) ? current : 'all';
}

function renderCandidates(payload) {
  const allItems = payload.candidates || [];
  const items = sortedAndFilteredCandidates(allItems);
  const availability = payload.availability || {};
  const total = availability.total || allItems.length;
  const untested = availability.untested || 0;
  const hiddenByFilters = Math.max(0, total - items.length);
  $('outboundHeading').textContent = `Доступные outbound (доступно ${availability.available || 0}, недоступно ${availability.unavailable || 0}${untested ? `, не проверено ${untested}` : ''})`;
  $('candidateCount').textContent = `Показано ${items.length} из ${total}` +
    (hiddenByFilters ? ` · скрыто фильтрами ${hiddenByFilters}` : '');

  if (!items.length) {
    $('outboundList').innerHTML = '<div class="empty">Ни один outbound не соответствует выбранным фильтрам.</div>';
    return;
  }

  const operationRunning = Boolean(
    payload.jobs?.latency?.running || payload.jobs?.refresh?.running || payload.jobs?.switch?.running
  );
  $('outboundList').innerHTML = items.map((item) => `
    <article class="outbound-card ${item.active ? 'active' : ''} ${item.latency?.status === 'error' ? 'unavailable' : ''}">
      <div class="outbound-main">
        <div class="outbound-title-row">
          <span class="outbound-title" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
          <span class="protocol-chip">${escapeHtml(item.protocol)}</span>
          ${item.active ? '<span class="active-chip">АКТИВЕН</span>' : ''}
          ${item.draining ? '<span class="draining-chip">ЗАВЕРШАЕТ СОЕДИНЕНИЯ</span>' : ''}
        </div>
        <div class="outbound-meta" title="${escapeHtml(protocolMeta(item))}">${escapeHtml(protocolMeta(item))}</div>
      </div>
      <div class="outbound-actions">
        ${pingMarkup(item)}
        <button class="mini-button" data-test="${escapeHtml(item.id)}" ${operationRunning ? 'disabled' : ''}>Тест</button>
        <button class="mini-button select" data-select="${escapeHtml(item.id)}" ${item.active || operationRunning ? 'disabled' : ''}>Выбрать</button>
      </div>
    </article>`).join('');

  document.querySelectorAll('[data-select]').forEach((button) => {
    button.addEventListener('click', () => selectCandidate(button.dataset.select));
  });
  document.querySelectorAll('[data-test]').forEach((button) => {
    button.addEventListener('click', () => testCandidates(button.dataset.test));
  });
}

function renderRuntimeStatus(payload) {
  const selector = payload.selector || {};
  const hint = $('selectorHint');
  hint.className = 'traffic-hint';

  if (!payload.xray_running) {
    $('statusDot').className = 'status-dot bad';
    $('xrayState').textContent = 'Xray остановлен';
    hint.textContent = 'Активный слот не работает';
    hint.classList.add('bad');
    return;
  }

  $('statusDot').className = 'status-dot ok';
  $('xrayState').textContent = 'Xray работает';

  if (!selector.configured) {
    hint.textContent = 'Управление внешним selector отключено; текущий слот остаётся активным без автоматического переключения';
    hint.classList.add('warn');
    return;
  }
  if (!selector.available) {
    $('statusDot').className = 'status-dot warn';
    hint.textContent = selector.error || 'Внешний selector недоступен';
    hint.classList.add('warn');
    return;
  }
  hint.textContent = `Selector ${payload.blue_green?.selector_tag || 'xray-active'}: ${selector.current || '—'}`;
  if (!selector.connections_supported) {
    $('statusDot').className = 'status-dot warn';
    hint.textContent += ` · ${selector.error || 'учёт соединений недоступен'}; старый слот не будет остановлен автоматически`;
    hint.classList.add('warn');
  }
}

function initializeSettings(payload) {
  if (state.settingsInitialized) return;
  const checker = payload.auto_checker || {};
  const subscription = payload.subscription || {};
  const ui = payload.ui_settings || {};
  $('autoCheckerEnabled').checked = Boolean(checker.enabled);
  $('autoSwitchBestEnabled').checked = Boolean(checker.switch_to_best);
  $('autoCheckInterval').value = checker.interval_seconds ?? 600;
  $('autoCheckFailures').value = checker.failure_threshold ?? 3;
  $('autoSwitchExcludedCountries').value = checker.excluded_countries ?? 'RU';
  $('autoSwitchMinPingDelta').value = checker.min_ping_delta_ms ?? 100;
  $('subscriptionUrl').value = subscription.url || '';
  $('subscriptionInterval').value = subscription.update_interval_hours ?? 1;
  $('sortSelect').value = ui.sort || 'ping-asc';
  $('maxPing').value = ui.max_ping_ms ?? 1000;
  $('hideUnavailable').checked = Boolean(ui.hide_unavailable);
  renderProtocols(payload.protocols || []);
  $('protocolFilter').value = ui.protocol_filter || 'all';
  state.savedAutoChecker = autoCheckerFormValues();
  state.savedSubscription = subscriptionFormValues();
  updateSaveButtons();
  state.settingsInitialized = true;
}

function render(payload) {
  state.payload = payload;
  initializeSettings(payload);
  renderProtocols(payload.protocols || []);
  const backendProtocol = payload.ui_settings?.protocol_filter || 'all';
  if (!$('protocolFilter').matches(':focus')) $('protocolFilter').value = backendProtocol;

  renderRuntimeStatus(payload);
  const active = payload.active;
  $('activeName').textContent = active?.name || 'Активный outbound не определён';
  $('activeMeta').textContent = active ? `${active.protocol} · ${protocolMeta(active)}` : 'Ожидание трафика';
  const blueGreen = payload.blue_green || {};
  const activeSlot = blueGreen.slots?.[blueGreen.active_slot];
  if (activeSlot) {
    $('activeMeta').textContent += ` · ${blueGreen.active_slot} · SOCKS ${activeSlot.socks_tcp}`;
  }
  const drainingSlot = Object.values(blueGreen.slots || {}).find((slot) => slot.draining);
  if (drainingSlot) {
    if (drainingSlot.drain_connections > 0) {
      $('activeMeta').textContent += ` · ${drainingSlot.tag} завершает старые соединения в количестве: ${drainingSlot.drain_connections}`;
    } else {
      const drainState = drainingSlot.drain_zero_since ? 'защитная пауза' : 'проверка активности';
      $('activeMeta').textContent += ` · ${drainingSlot.tag} завершает обслуживание старых соединений: ${drainState}`;
    }
  }
  if (payload.route_mismatch && payload.selected_active) {
    $('activeMeta').textContent += ` · выбран в конфигурации: ${payload.selected_active.name}`;
  }

  const checker = payload.auto_checker || {};
  $('autoCheckerState').textContent = checker.enabled ? 'Включён' : 'Выключен';
  if (checker.enabled) {
    const result = checker.last_error
      ? `Последняя ошибка: ${checker.last_error}`
      : `Последняя проверка: ${formatRelative(checker.last_check_at)}`;
    const bestMode = checker.switch_to_best
      ? ` · автопереключение включено · разница от ${checker.min_ping_delta_ms} мс · исключение ${checker.excluded_countries || 'нет'}`
      : '';
    $('autoCheckerMeta').textContent = `${checker.interval_seconds} с · порог ${checker.failure_threshold} · ошибок ${checker.current_failures}${bestMode}. ${result}`;
  } else {
    $('autoCheckerMeta').textContent = checker.switch_to_best
      ? 'Авто-чекер выключен; автопереключение начнёт работать после его включения'
      : 'Автоматическая проверка и переключение отключены';
  }

  const subscription = payload.subscription || {};
  if (subscription.error) {
    $('subscriptionState').textContent = 'Ошибка синхронизации';
    $('subscriptionMeta').textContent = `${subscription.error} · ${formatRelative(subscription.last_error_at || subscription.last_attempt_at)}`;
  } else if (subscription.last_success_at) {
    $('subscriptionState').textContent = 'Синхронизирована';
    $('subscriptionMeta').textContent = `Подписка успешно обновлена ${formatRelative(subscription.last_success_at)}`;
  } else {
    $('subscriptionState').textContent = 'Нет данных';
    $('subscriptionMeta').textContent = 'Успешная синхронизация ещё не выполнялась';
  }

  $('versionBadge').textContent = `v${payload.version}`;
  state.releaseNotes = Array.isArray(payload.release_notes?.items) ? payload.release_notes.items.map(String) : [];
  $('changelogTitle').textContent = `Версия ${payload.release_notes?.version || payload.version}`;
  const changelogList = $('changelogList');
  changelogList.replaceChildren(...(state.releaseNotes.length ? state.releaseNotes : ['Изменения для этой версии не указаны.']).map((item) => {
    const li = document.createElement('li');
    li.innerHTML = escapeHtml(item).replace(/`([^`]+)`/g, '<code>$1</code>');
    return li;
  }));
  $('versionLine').textContent = `Приложение ${payload.version} · ${payload.xray_version}`;
  $('syncNote').textContent = subscription.next_update_at
    ? `Следующее обновление: ${formatDateTime(subscription.next_update_at)}`
    : 'Автообновление подписки выключено';

  const latencyJob = payload.jobs?.latency || {};
  const refreshJob = payload.jobs?.refresh || {};
  const switchJob = payload.jobs?.switch || {};
  const running = Boolean(latencyJob.running || refreshJob.running || switchJob.running);
  $('testAllButton').disabled = running;
  $('refreshButton').disabled = running;
  if (running) {
    $('jobBanner').classList.remove('hidden');
    $('jobBanner').textContent = switchJob.running
      ? switchJob.message
      : (latencyJob.running
        ? `${latencyJob.message} (${latencyJob.progress}/${latencyJob.total})`
        : refreshJob.message);
  } else {
    $('jobBanner').classList.add('hidden');
  }
  renderCandidates(payload);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function setLogSearchControls(matchCount) {
  const hasMatches = matchCount > 0;
  $('logsSearchPrevious').disabled = !hasMatches;
  $('logsSearchNext').disabled = !hasMatches;
  $('logsSearchCount').textContent = hasMatches
    ? `${state.logSearchIndex + 1} / ${matchCount}`
    : '0 / 0';
}

function renderLogs({ scrollToMatch = false, queryChanged = false } = {}) {
  const content = $('logsContent');
  const query = $('logsSearchInput').value.trim();
  const plainText = state.logsLines.length ? state.logsLines.join('\n') : 'Логи пока пусты.';

  if (!query) {
    state.logSearchQuery = '';
    state.logSearchIndex = -1;
    content.textContent = plainText;
    setLogSearchControls(0);
    return;
  }

  const expression = new RegExp(escapeRegExp(query), 'gi');
  let matchNumber = 0;
  const renderedLines = state.logsLines.map((line) => {
    let cursor = 0;
    let rendered = '';
    expression.lastIndex = 0;
    for (const match of line.matchAll(expression)) {
      const start = match.index ?? 0;
      const value = match[0];
      rendered += escapeHtml(line.slice(cursor, start));
      rendered += `<mark class="log-search-match" data-log-match="${matchNumber}">${escapeHtml(value)}</mark>`;
      matchNumber += 1;
      cursor = start + value.length;
      if (!value.length) expression.lastIndex += 1;
    }
    rendered += escapeHtml(line.slice(cursor));
    return rendered;
  });

  state.logSearchQuery = query;
  if (matchNumber === 0) {
    state.logSearchIndex = -1;
    content.innerHTML = renderedLines.length ? renderedLines.join('\n') : escapeHtml(plainText);
    setLogSearchControls(0);
    return;
  }

  if (queryChanged || state.logSearchIndex < 0) state.logSearchIndex = 0;
  state.logSearchIndex = Math.min(state.logSearchIndex, matchNumber - 1);
  content.innerHTML = renderedLines.join('\n');

  const matches = [...content.querySelectorAll('.log-search-match')];
  const selected = matches[state.logSearchIndex];
  selected?.classList.add('current');
  setLogSearchControls(matchNumber);
  if (scrollToMatch) selected?.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

function moveLogSearch(direction) {
  const matches = [...$('logsContent').querySelectorAll('.log-search-match')];
  if (!matches.length) return;
  state.logSearchIndex = (state.logSearchIndex + direction + matches.length) % matches.length;
  matches.forEach((match) => match.classList.remove('current'));
  const selected = matches[state.logSearchIndex];
  selected.classList.add('current');
  setLogSearchControls(matches.length);
  selected.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

async function fetchLogs(forceScroll = false) {
  const content = $('logsContent');
  const wasNearBottom = content.scrollHeight - content.scrollTop - content.clientHeight < 80;
  try {
    const response = await fetch(api('api/logs?limit=2000'), { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    state.logsLines = Array.isArray(payload.lines) ? payload.lines.map((line) => String(line)) : [];
    state.logsTotal = Number(payload.total) || state.logsLines.length;
    renderLogs();
    $('logsMeta').textContent = `Показано строк: ${state.logsLines.length}${state.logsTotal > state.logsLines.length ? ` из ${state.logsTotal}` : ''}`;
    if (!state.logSearchQuery && (forceScroll || wasNearBottom)) content.scrollTop = content.scrollHeight;
  } catch (error) {
    state.logsLines = [];
    content.textContent = `Не удалось загрузить логи: ${error.message}`;
    $('logsMeta').textContent = 'Ошибка загрузки';
    setLogSearchControls(0);
  }
}

function openLogs(event) {
  event?.preventDefault();
  event?.stopPropagation();
  if (state.logsOpen) return;
  closeChangelog();
  state.logsOpen = true;
  $('logsModal').classList.remove('hidden');
  document.body.classList.add('modal-open');
  fetchLogs(true);
  window.clearInterval(state.logsTimer);
  state.logsTimer = window.setInterval(() => fetchLogs(false), 2000);
}

function closeLogs() {
  state.logsOpen = false;
  $('logsModal').classList.add('hidden');
  document.body.classList.remove('modal-open');
  window.clearInterval(state.logsTimer);
  state.logsTimer = null;
}

function scrollLogsToStart() {
  $('logsContent').scrollTo({ top: 0, behavior: 'smooth' });
}

function scrollLogsToEnd() {
  const content = $('logsContent');
  content.scrollTo({ top: content.scrollHeight, behavior: 'smooth' });
}

function setLogWrapDisabled(disabled) {
  state.logWrapDisabled = Boolean(disabled);
  const content = $('logsContent');
  const button = $('logsWrapToggle');
  content.classList.toggle('no-wrap', state.logWrapDisabled);
  button.classList.toggle('active', state.logWrapDisabled);
  button.setAttribute('aria-pressed', String(state.logWrapDisabled));
  const action = state.logWrapDisabled ? 'Включить перенос строк' : 'Выключить перенос строк';
  button.setAttribute('aria-label', action);
  button.title = action;
}

function toggleLogWrap() {
  setLogWrapDisabled(!state.logWrapDisabled);
}

function openChangelog() {
  if (state.changelogOpen) return;
  state.changelogOpen = true;
  $('changelogPopover').classList.remove('hidden');
  $('versionBadge').setAttribute('aria-expanded', 'true');
}

function closeChangelog() {
  state.changelogOpen = false;
  $('changelogPopover').classList.add('hidden');
  $('versionBadge').setAttribute('aria-expanded', 'false');
}

function toggleChangelog(event) {
  event?.preventDefault();
  event?.stopPropagation();
  if (state.changelogOpen) closeChangelog();
  else openChangelog();
}

async function fetchStatus() {
  try {
    const response = await fetch(api('api/status'), { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    $('statusDot').className = 'status-dot bad';
    $('xrayState').textContent = 'Интерфейс недоступен';
    toast(`Ошибка: ${error.message}`, true);
  }
}

async function post(path, body = {}) {
  const response = await fetch(api(path), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function toast(message, isError = false) {
  const element = $('toast');
  element.textContent = message;
  element.className = `toast visible${isError ? ' error' : ''}`;
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => { element.className = 'toast'; }, 5000);
}

async function selectCandidate(id) {
  try {
    toast('Переключение outbound…');
    await post('api/select', { id });
    toast('Outbound переключён');
    await fetchStatus();
  } catch (error) { toast(`Ошибка: ${error.message}`, true); }
}

async function testCandidates(id = '') {
  try {
    await post('api/test', id ? { id } : {});
    toast(id ? 'Запущена проверка outbound' : 'Запущена проверка всех outbound');
    await fetchStatus();
  } catch (error) { toast(`Ошибка: ${error.message}`, true); }
}

async function refreshSubscription() {
  try {
    await post('api/refresh');
    toast('Обновление подписки запущено');
    await fetchStatus();
  } catch (error) { toast(`Ошибка: ${error.message}`, true); }
}

function showRestartModal(changes) {
  state.restartChanges = changes;
  $('restartModal').classList.remove('hidden');
}

function hideRestartModal() {
  state.restartChanges = null;
  $('restartModal').classList.add('hidden');
}

async function saveSettings(changes, successMessage) {
  try {
    const result = await post('api/settings', { changes });
    if (result.restart_required?.length) {
      showRestartModal(changes);
      return false;
    }
    toast(successMessage);
    if (!result.supervisor_synced && result.supervisor_error) {
      console.warn(result.supervisor_error);
    }
    await fetchStatus();
    return true;
  } catch (error) {
    toast(`Ошибка сохранения: ${error.message}`, true);
    return false;
  }
}

async function saveAutoChecker() {
  const changes = autoCheckerFormValues();
  $('autoSwitchExcludedCountries').value = changes.auto_switch_excluded_countries;
  if (await saveSettings(changes, 'Настройки авто-чекера сохранены')) {
    state.savedAutoChecker = { ...changes };
    updateSaveButtons();
  }
}

async function saveSubscriptionSettings() {
  const changes = subscriptionFormValues();
  if (await saveSettings(changes, 'Настройки подписки сохранены')) {
    state.savedSubscription = { ...changes };
    updateSaveButtons();
  }
}

function scheduleFilterSave() {
  if (state.payload) renderCandidates(state.payload);
  window.clearTimeout(state.filterSaveTimer);
  state.filterSaveTimer = window.setTimeout(() => {
    const ui = currentUiSettings();
    saveSettings({
      ui_sort: ui.sort,
      ui_protocol_filter: ui.protocol_filter,
      ui_max_ping_ms: ui.max_ping_ms,
      ui_hide_unavailable: ui.hide_unavailable,
    }, 'Фильтры сохранены');
  }, 500);
}

$('versionBadge').addEventListener('click', toggleChangelog);
$('closeChangelogButton').addEventListener('click', (event) => { event.stopPropagation(); closeChangelog(); });
$('logsButton').addEventListener('click', openLogs);
$('closeLogsButton').addEventListener('click', closeLogs);
$('logsTopButton').addEventListener('click', scrollLogsToStart);
$('logsBottomButton').addEventListener('click', scrollLogsToEnd);
$('logsSearchPrevious').addEventListener('click', () => moveLogSearch(-1));
$('logsSearchNext').addEventListener('click', () => moveLogSearch(1));
$('logsWrapToggle').addEventListener('click', toggleLogWrap);
$('logsSearchInput').addEventListener('input', () => {
  state.logSearchIndex = -1;
  renderLogs({ scrollToMatch: true, queryChanged: true });
});
$('logsSearchInput').addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  moveLogSearch(event.shiftKey ? -1 : 1);
});
document.addEventListener('click', (event) => {
  if (!state.changelogOpen) return;
  const target = event.target instanceof Element ? event.target : null;
  if (target?.closest('#changelogPopover, #versionBadge')) return;
  closeChangelog();
});
$('logsModal').addEventListener('click', (event) => {
  if (event.target === $('logsModal')) closeLogs();
});
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (state.logsOpen) closeLogs();
  else if (state.changelogOpen) closeChangelog();
});
$('testAllButton').addEventListener('click', () => testCandidates());
$('refreshButton').addEventListener('click', refreshSubscription);
$('saveAutoChecker').addEventListener('click', saveAutoChecker);
$('saveSubscription').addEventListener('click', saveSubscriptionSettings);
['autoCheckerEnabled', 'autoSwitchBestEnabled', 'autoCheckInterval', 'autoCheckFailures', 'autoSwitchExcludedCountries', 'autoSwitchMinPingDelta'].forEach((id) => {
  $(id).addEventListener(['autoCheckerEnabled', 'autoSwitchBestEnabled'].includes(id) ? 'change' : 'input', updateSaveButtons);
});
['subscriptionUrl', 'subscriptionInterval'].forEach((id) => $(id).addEventListener('input', updateSaveButtons));
['sortSelect', 'protocolFilter', 'maxPing', 'hideUnavailable'].forEach((id) => {
  $(id).addEventListener(id === 'maxPing' ? 'input' : 'change', scheduleFilterSave);
});
$('applyRestartButton').addEventListener('click', () => {
  hideRestartModal();
  toast('Настройки сохранены. Перезапустите приложение из Home Assistant.', true);
});
$('saveOnlyButton').addEventListener('click', hideRestartModal);
$('cancelRestartButton').addEventListener('click', hideRestartModal);

fetchStatus();
setInterval(fetchStatus, 3000);
