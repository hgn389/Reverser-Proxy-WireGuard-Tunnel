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

  function copyButton(text, label) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'guide-copy';
    button.setAttribute('aria-label', label);
    button.title = label;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M9 5H5v14h10v-4M9 3h10v12H9z');
    svg.append(path);
    button.append(svg);
    let timer;
    button.addEventListener('click', async () => {
      clearTimeout(timer);
      try {
        try {
          if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('Clipboard unavailable');
          await navigator.clipboard.writeText(text);
        } catch {
          fallbackCopy(text);
        }
        status.textContent = labels.copied;
        button.setAttribute('aria-label', labels.copied);
        button.title = labels.copied;
      } catch {
        status.textContent = labels.failed;
        button.title = labels.failed;
      }
      timer = setTimeout(() => {
        button.setAttribute('aria-label', label);
        button.title = label;
      }, 2000);
    });
    return button;
  }

  let status;
  function initialize() {
    const blocks = document.querySelectorAll('pre > code');
    if (!blocks.length) return;
    status = document.createElement('span');
    status.className = 'guide-copy-status';
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
            row.append(command, copyButton(entry.command, labels.command));
            container.append(row);
          }
        });
        pre.replaceWith(container);
      } else {
        container.className = 'guide-snippet';
        pre.replaceWith(container);
        container.append(pre, copyButton(source, labels.snippet));
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
})();
