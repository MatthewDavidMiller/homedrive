// Photo backup from a phone's browser: see crates/hd-server/src/photos.rs.
//
// For each picked file: hash it in pieces, ask the server which files it
// already has and which pieces it lacks, send those pieces one request
// each, and commit. Nothing here can replace or delete anything in the
// drive; the server keeps a file that reuses a name as a separate copy.
'use strict';

(function () {
  var form = document.getElementById('photo-form');
  if (!form) {
    return;
  }
  var csrf = form.getAttribute('data-csrf');
  var PIECE = Number(form.getAttribute('data-piece'));
  var CHECK_FILES = Number(form.getAttribute('data-check-files'));
  var CHECK_PIECES = Number(form.getAttribute('data-check-pieces'));
  var deviceInput = document.getElementById('device');
  var deviceEcho = document.getElementById('device-echo');
  var picker = document.getElementById('photos');
  var startButton = document.getElementById('start');
  var stopButton = document.getElementById('stop');
  var statusLine = document.getElementById('photo-status');
  var bar = document.getElementById('photo-progress');
  var log = document.getElementById('photo-log');
  var KEY = 'homedrive-photo-device';
  var stopping = false;
  var wakeLock = null;

  try {
    var saved = window.localStorage.getItem(KEY);
    if (saved) {
      deviceInput.value = saved;
    }
  } catch (e) {
    // Private browsing: the default name stays.
  }
  function echo() {
    deviceEcho.textContent = deviceInput.value.trim() || '…';
  }
  echo();
  deviceInput.addEventListener('input', echo);

  function say(text) {
    statusLine.textContent = text;
  }

  function note(name, text, tone) {
    var li = document.createElement('li');
    if (tone) {
      li.className = 'photo-' + tone;
    }
    var strong = document.createElement('strong');
    strong.textContent = name;
    li.appendChild(strong);
    li.appendChild(document.createTextNode(' ' + text));
    log.appendChild(li);
  }

  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function hex(buffer) {
    var bytes = new Uint8Array(buffer);
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out;
  }

  function size(bytes) {
    if (bytes < 1024 * 1024) {
      return Math.max(1, Math.round(bytes / 1024)) + ' KB';
    }
    if (bytes < 1024 * 1024 * 1024) {
      return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  async function stayAwake() {
    try {
      if (navigator.wakeLock && document.visibilityState === 'visible') {
        wakeLock = await navigator.wakeLock.request('screen');
      }
    } catch (e) {
      wakeLock = null;
    }
  }

  // A wake lock ends when the page is hidden; ask again on return.
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible' && startButton.disabled) {
      stayAwake();
    }
  });

  function Failure(message) {
    this.message = message;
  }

  // POSTs to the server, waiting out a lost connection, a busy proxy or a
  // restarting server (a locked screen suspends the page, and its requests
  // fail). Other answers are returned as they are.
  async function post(path, body, isJson) {
    for (var attempt = 0; ; attempt++) {
      var reply = null;
      try {
        reply = await fetch(path, {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: {
            'X-CSRF-Token': csrf,
            'Content-Type': isJson ? 'application/json' : 'application/octet-stream'
          },
          body: isJson ? JSON.stringify(body) : body
        });
      } catch (e) {
        reply = null;
      }
      var retry = !reply || reply.status === 429 || reply.status === 502 ||
        reply.status === 503 || reply.status === 504;
      if (!retry) {
        return reply;
      }
      if (stopping) {
        throw new Failure('stopped');
      }
      if (attempt >= 10) {
        throw new Failure(reply ? 'the server answered ' + reply.status : 'the connection failed');
      }
      say('Waiting for the connection…');
      await sleep(Math.min(30000, 1000 * Math.pow(2, attempt)));
    }
  }

  async function why(reply) {
    try {
      var body = await reply.json();
      if (body && body.error) {
        return body.error;
      }
    } catch (e) {
      // Not JSON.
    }
    return 'the server answered ' + reply.status;
  }

  async function postJson(path, body) {
    var reply = await post(path, body, true);
    if (reply.status === 403) {
      throw new Failure('the page expired; reload it and pick the photos again');
    }
    return reply;
  }

  // The SHA-256 of each piece, read one piece at a time so a long video
  // never sits in memory whole.
  async function hashPieces(file) {
    var n = Math.ceil(file.size / PIECE);
    var out = [];
    for (var i = 0; i < n; i++) {
      var data = await file.slice(i * PIECE, Math.min(file.size, (i + 1) * PIECE)).arrayBuffer();
      out.push(hex(await crypto.subtle.digest('SHA-256', data)));
      if (stopping) {
        throw new Failure('stopped');
      }
    }
    return out;
  }

  // Sends the listed pieces of a file, then commits it. Returns the
  // server's {path, status}.
  async function send(device, item, missing, progress) {
    for (var round = 0; ; round++) {
      for (var k = 0; k < missing.length; k++) {
        if (stopping) {
          throw new Failure('stopped');
        }
        var i = missing[k];
        var start = i * PIECE;
        var data = await item.file.slice(start, Math.min(item.file.size, start + PIECE)).arrayBuffer();
        var reply = await post('/photos/piece?id=' + item.pieces[i], data, false);
        if (reply.status === 403) {
          throw new Failure('the page expired; reload it and pick the photos again');
        }
        if (reply.status === 422) {
          throw new Failure('the file changed while it was read; pick it again');
        }
        if (reply.status !== 200 && reply.status !== 201) {
          throw new Failure(await why(reply));
        }
        progress(data.byteLength);
      }
      var commit = await postJson('/photos/commit', {
        device: device,
        name: item.file.name,
        size: item.file.size,
        mtime: item.file.lastModified || 0,
        pieces: item.pieces
      });
      if (commit.status === 200) {
        return commit.json();
      }
      if (commit.status === 409 && round === 0) {
        var body = null;
        try {
          body = await commit.json();
        } catch (e) {
          body = null;
        }
        if (body && body.missing && body.missing.length) {
          // A piece went missing since the check (or could not be read):
          // send those again, once.
          missing = body.missing;
          continue;
        }
        throw new Failure(body && body.error ? body.error : 'the server answered 409');
      }
      throw new Failure(await why(commit));
    }
  }

  async function run(device, files) {
    var counts = { uploaded: 0, copies: 0, had: 0, failed: 0 };
    var totalBytes = 0;
    files.forEach(function (f) {
      totalBytes += f.size;
    });
    var hashed = 0;
    var sent = 0;
    var toSend = 0;
    bar.hidden = false;
    bar.max = 1;
    bar.value = 0;

    function show() {
      bar.value = totalBytes ? (hashed + sent) / (totalBytes + toSend) : 1;
    }

    var next = 0;
    while (next < files.length && !stopping) {
      // A batch: hash until it is as large as one check may be.
      var batch = [];
      var pieceCount = 0;
      while (next < files.length && batch.length < CHECK_FILES) {
        var file = files[next];
        var n = Math.ceil(file.size / PIECE);
        if (batch.length && pieceCount + n > CHECK_PIECES) {
          break;
        }
        say('Checking ' + (next + 1) + ' of ' + files.length + ': ' + file.name);
        try {
          batch.push({ file: file, pieces: await hashPieces(file) });
          pieceCount += n;
        } catch (e) {
          if (e instanceof Failure && e.message === 'stopped') {
            break;
          }
          counts.failed++;
          note(file.name, 'could not be read: ' + (e.message || e), 'danger');
        }
        hashed += file.size;
        show();
        next++;
        if (n > CHECK_PIECES) {
          // Larger than one check can name; the server refuses it below.
          break;
        }
      }
      if (!batch.length) {
        continue;
      }
      var reply = await postJson('/photos/check', {
        device: device,
        files: batch.map(function (item) {
          return { size: item.file.size, pieces: item.pieces };
        })
      });
      if (reply.status !== 200) {
        var reason = await why(reply);
        batch.forEach(function (item) {
          counts.failed++;
          note(item.file.name, 'was not checked: ' + reason, 'danger');
        });
        continue;
      }
      var answers = (await reply.json()).files;
      for (var j = 0; j < batch.length && !stopping; j++) {
        var item = batch[j];
        var answer = answers[j];
        if (answer.have) {
          counts.had++;
          continue;
        }
        var bytes = 0;
        answer.missing.forEach(function (i) {
          bytes += Math.min(PIECE, item.file.size - i * PIECE);
        });
        toSend += bytes;
        say('Uploading ' + item.file.name + ' (' + size(item.file.size) + ')');
        try {
          var done = await send(device, item, answer.missing, function (n) {
            sent += n;
            show();
          });
          if (done.status === 'copy') {
            counts.copies++;
            note(item.file.name, 'was stored as ' + done.path + ', since a different photo has its name.', 'warning');
          } else if (done.status === 'unchanged') {
            counts.had++;
          } else {
            counts.uploaded++;
          }
        } catch (e) {
          if (e instanceof Failure && e.message === 'stopped') {
            break;
          }
          counts.failed++;
          note(item.file.name, 'was not backed up: ' + (e.message || e), 'danger');
        }
      }
    }
    var parts = [];
    parts.push(counts.uploaded + ' uploaded');
    if (counts.copies) {
      parts.push(counts.copies + ' kept as copies');
    }
    parts.push(counts.had + ' already in the drive');
    if (counts.failed) {
      parts.push(counts.failed + ' not backed up');
    }
    var left = stopping ? ' Pick the photos again to carry on.' : '';
    if (counts.failed) {
      left += ' Keep the photos listed as not backed up on the phone.';
    }
    say((stopping ? 'Stopped: ' : 'Done: ') + parts.join(', ') + '.' + left);
    if (!stopping && !counts.failed) {
      bar.value = 1;
    }
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (!window.crypto || !crypto.subtle) {
      say('This browser cannot check photos here: open the page over https.');
      return;
    }
    var device = deviceInput.value.trim();
    var files = Array.prototype.slice.call(picker.files || []);
    if (!device || !files.length) {
      say('Name the device and pick some photos first.');
      return;
    }
    try {
      window.localStorage.setItem(KEY, device);
    } catch (e) {
      // Not remembered; nothing else depends on it.
    }
    stopping = false;
    log.textContent = '';
    startButton.disabled = true;
    picker.disabled = true;
    deviceInput.disabled = true;
    stopButton.hidden = false;
    await stayAwake();
    try {
      await run(device, files);
    } catch (e) {
      say('The backup stopped: ' + (e.message || e) + '. Photos listed above as failed were not stored; the rest are safe.');
    } finally {
      startButton.disabled = false;
      picker.disabled = false;
      deviceInput.disabled = false;
      stopButton.hidden = true;
      if (wakeLock) {
        wakeLock.release().catch(function () {});
        wakeLock = null;
      }
    }
  });

  stopButton.addEventListener('click', function () {
    stopping = true;
    say('Stopping after the current piece…');
  });
})();
