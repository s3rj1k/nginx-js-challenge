package main

/*
 - https://projects.lukehaas.me/css-loaders/
 - https://jshint.com/

 - https://cdnjs.com/libraries/js-sha1
 - https://cdnjs.cloudflare.com/ajax/libs/js-sha1/0.6.0/sha1.min.js

 - https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST
 - https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams
*/

const challengeHTMLTemplate = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
    <meta http-equiv="refresh" content="30"/>
    <title>Loading...</title>
    <style>
      .center {
        margin: 0;
        position: absolute;
        top: 50%;
        left: 50%;
        -ms-transform: translate(-50%, -50%);
        transform: translate(-50%, -50%);
      }

      .loader, .loader:before, .loader:after {
        border-radius: 50%;
        width: 2.5em;
        height: 2.5em;
        -webkit-animation-fill-mode: both;
        animation-fill-mode: both;
        -webkit-animation: load7 1.8s infinite ease-in-out;
        animation: load7 1.8s infinite ease-in-out;
      }

      .loader {
        color: #b00015;
        font-size: 10px;
        margin: 80px auto;
        position: relative;
        text-indent: -9999em;
        -webkit-transform: translateZ(0);
        -ms-transform: translateZ(0);
        transform: translateZ(0);
        -webkit-animation-delay: -0.16s;
        animation-delay: -0.16s;
      }

      .loader:before, .loader:after {
        content: '';
        position: absolute;
        top: 0;
      }

      .loader:before {
        left: -3.5em;
        -webkit-animation-delay: -0.32s;
        animation-delay: -0.32s;
      }

      .loader:after {
        left: 3.5em;
      }

      @-webkit-keyframes load7 {
        0%,
        80%,
        100% {
          box-shadow: 0 2.5em 0 -1.3em;
        }
        40% {
          box-shadow: 0 2.5em 0 0;
        }
      }

      @keyframes load7 {
        0%,
        80%,
        100% {
          box-shadow: 0 2.5em 0 -1.3em;
        }
        40% {
          box-shadow: 0 2.5em 0 0;
        }
      }
    </style>

    <script type="text/javascript" src="{{ .JSHashLibraryURL }}"></script>

    <script>
      function getRandomNumber(max) {
        return Math.floor(Math.random() * max);
      }

      function getCookie(name) {
        var matches = document.cookie.match(new RegExp(
          '(?:^|; )' + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'
        ));

        return matches ? decodeURIComponent(matches[1]) : undefined;
      }

      function deleteCookie(name) {
        document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
      }

      function getStringHash(s) {
        return sha1(s);
      }

      function computeResponce(challenge, response, maxNum) {
        var kChallenge = getCookie(challenge);

        deleteCookie(challenge);

        var computeTimer = setInterval(function() {
          var nonce = getRandomNumber(maxNum);
          var nChallenge = getStringHash(navigator.userAgent + nonce);

          if (kChallenge == nChallenge) {
            clearInterval(computeTimer);

            var xhr = new XMLHttpRequest();
            var data = new URLSearchParams();

            data.append(challenge, kChallenge);
            data.append(response, nonce);

            xhr.open('POST', '/', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
            xhr.send(data);
            xhr.onreadystatechange = function() {
              if (this.readyState != 4) return;

              window.location.assign(window.location.href);
              document.location.reload(true);
            };
          }
        }, 10);
      }
    </script>

    <script>
      document.addEventListener('DOMContentLoaded', function() {
        computeResponce('{{ .ChallengeName }}', '{{ .ResponseName }}', '{{ .MaxNonce }}');
      });
    </script>
  </head>
  <body>
    <div class="center">
      <div class="loader"></div>
    </div>
  </body>
</html>
`

const challengeLightHTMLTemplate = `
<script type="text/javascript" src="{{ .JSHashLibraryURL }}"></script>

<script>
  function getRandomNumber(max) {
    return Math.floor(Math.random() * max);
  }

  function getCookie(name) {
    var matches = document.cookie.match(new RegExp(
      '(?:^|; )' + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'
    ));

    return matches ? decodeURIComponent(matches[1]) : undefined;
  }

  function deleteCookie(name) {
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
  }

  function getStringHash(s) {
    return sha1(s);
  }

  function computeResponce(challenge, response, maxNum) {
    var kChallenge = getCookie(challenge);

    deleteCookie(challenge);

    var computeTimer = setInterval(function() {
      var nonce = getRandomNumber(maxNum);
      var nChallenge = getStringHash(navigator.userAgent + nonce);

      if (kChallenge == nChallenge) {
        clearInterval(computeTimer);

        var xhr = new XMLHttpRequest();
        var data = new URLSearchParams();

        data.append(challenge, kChallenge);
        data.append(response, nonce);

        xhr.open('POST', '/', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        xhr.send(data);
        xhr.onreadystatechange = function() {
          if (this.readyState != 4) return;

          window.location.assign(window.location.href);
          document.location.reload(true);
        };
      }
    }, 10);
  }
</script>

<script>
  document.addEventListener('DOMContentLoaded', function() {
    computeResponce('{{ .ChallengeName }}', '{{ .ResponseName }}', '{{ .MaxNonce }}');
  });
</script>
`
