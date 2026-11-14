(() => {
  'use strict';

  const labels = document.documentElement.lang.toLowerCase().startsWith('vi')
    ? { command: 'Sao chép lệnh', snippet: 'Sao chép toàn bộ đoạn mã', copied: 'Đã sao chép', failed: 'Không thể sao chép. Hãy chọn và sao chép thủ công.' }
    : { command: 'Copy command', snippet: 'Copy whole snippet', copied: 'Copied', failed: 'Copy failed. Select and copy the text manually.' };

  function shellEntries(source) {
    const entries = [];
    let pending = '';
    let quote = '';
    let continuing = false;
    let commands = 0;
    for (const line of source.replace(/\r\n?/g, '\n').split('\n')) {
      let escaped = false;
      let comment = -1;
      for (let i = 0; i < line.length; i++) {
        const character = line[i];
        if (escaped) {
          escaped = false;
        } else if (character === '\\' && quote !== "'") {
          escaped = true;
        } else if (quote) {
          if (character === quote) quote = '';
        } else if (character === '"' || character === "'") {
          quote = character;
        } else if (character === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
          comment = i;
          break;
        }
      }
      const content = comment < 0 ? line : line.slice(0, comment);
      pending += escaped ? content.slice(0, -1) : content;
      continuing = escaped;
      if (continuing) continue;
      // Multiline strings and heredocs need their original newlines, not command rows.
      if (quote) return null;
      const command = pending.trim();
      if (command) {
        if (!/^(?:sudo|curl|git|cd|ping|ip|tailscale|scp|rpctl|bash)(?:\s|$)/.test(command) || command.includes('<<')) return null;
        entries.push({ command });
        commands++;
      }
      if (comment >= 0) entries.push({ comment: line.slice(comment).replace(/^#\s?/, '') });
      pending = '';
    }
    return continuing || !commands ? null : entries;
  }

  function fallbackCopy(text) {
    const active = document.activeElement;
    const selection = window.getSelection();
    const ranges = [];
    if (selection) {
      for (let i = 0; i < selection.rangeCount; i++) ranges.push(selection.getRangeAt(i).cloneRange());
    }
    const field = document.createElement('textarea');
    field.value = text;
    field.setAttribute('readonly', '');
    field.style.cssText = 'position:fixed;left:-9999px;top:0;';
    document.body.append(field);
    try {
      field.focus({ preventScroll: true });
      field.select();
      if (!document.execCommand('copy')) throw new Error('Copy unavailable');
    } finally {
      field.remove();
      if (active && typeof active.focus === 'function') active.focus({ preventScroll: true });
      if (selection) {
        selection.removeAllRanges();
        ranges.forEach(range => selection.addRange(range));
      }
    }
  }

  function enableCopy(element, text, label) {
    element.classList.add('guide-copy-target');
    element.setAttribute('role', 'button');
    element.tabIndex = 0;
    element.setAttribute('aria-label', label);
    element.title = label;
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    marker.setAttribute('class', 'guide-copy-marker');
    marker.setAttribute('viewBox', '0 0 24 24');
    marker.setAttribute('aria-hidden', 'true');
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '12');
    circle.setAttribute('cy', '12');
    circle.setAttribute('r', '9');
    const tick = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    tick.setAttribute('d', 'm8 12 3 3 5-6');
    marker.append(circle, tick);
    element.append(marker);
    const copy = async () => {
      try {
        try {
          if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('Clipboard unavailable');
          await navigator.clipboard.writeText(text);
        } catch {
          fallbackCopy(text);
        }
        status.textContent = '';
        status.hidden = false;
        status.textContent = labels.copied;
        element.classList.add('copied');
        element.setAttribute('aria-label', labels.copied);
        element.title = labels.copied;
      } catch {
        status.hidden = false;
        status.textContent = labels.failed;
        element.title = labels.failed;
      }
      clearTimeout(statusTimer);
      statusTimer = setTimeout(() => { status.hidden = true; }, 2500);
    };
    element.addEventListener('click', copy);
    element.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        void copy();
      }
    });
  }

  let status;
  let statusTimer;
  function initialize() {
    const blocks = document.querySelectorAll('pre > code');
    if (!blocks.length) return;
    status = document.createElement('span');
    status.className = 'guide-copy-status';
    status.hidden = true;
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    document.body.append(status);
    blocks.forEach(code => {
      const pre = code.parentElement;
      if (pre.dataset.guideCopyReady) return;
      pre.dataset.guideCopyReady = 'true';
      const source = code.textContent;
      const entries = shellEntries(source);
      const container = document.createElement('div');
      if (entries) {
        container.className = 'guide-commands';
        entries.forEach(entry => {
          if (entry.comment !== undefined) {
            const comment = document.createElement('p');
            comment.className = 'guide-command-comment';
            comment.textContent = entry.comment;
            container.append(comment);
          } else {
            const row = document.createElement('pre');
            row.className = 'guide-command';
            row.dataset.guideCopyReady = 'true';
            const command = document.createElement('code');
            command.textContent = entry.command;
            row.append(command);
            enableCopy(row, entry.command, labels.command);
            container.append(row);
          }
        });
        pre.replaceWith(container);
      } else {
        container.className = 'guide-snippet';
        pre.replaceWith(container);
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'guide-snippet-copy';
        const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        icon.setAttribute('viewBox', '0 0 24 24');
        icon.setAttribute('aria-hidden', 'true');
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', 'M9 5H5v14h10v-4M9 3h10v12H9z');
        icon.append(path);
        button.append(icon);
        enableCopy(button, source, labels.snippet);
        container.append(pre, button);
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
})();
