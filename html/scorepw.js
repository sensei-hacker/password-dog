function scoreDigits(password) {
  if (/^\d+$/.test(newpassword)) {
    return;
  }

  let i, years;

  if ( "01234567890".includes(password) || "09876543210".includes(password) ) {
    return 2;
  }

  years = set();
  i = 1940;

  while (i < 2050) {
    years.add(i.toString());
    i += 1;
  }

  if ( years.has(password) ) {
    return 2;
  }

  return password.length;
}

function scoreTime() {
    if (meter.value < 11) {
        document.getElementById('timeunit').innerText = "seconds";
    } else if (meter.value < 14) {
        document.getElementById('timeunit').innerText = "minutes";
    } else if (meter.value < 17) {
        document.getElementById('timeunit').innerText = "hours";
    } else if (meter.value < 18) {
        document.getElementById('timeunit').innerText = "days";
    } else if (meter.value < 19) {
        document.getElementById('timeunit').innerText = "weeks";
    } else if (meter.value < 20) {
        document.getElementById('timeunit').innerText = "months";
    }  else {
        document.getElementById('timeunit').innerText = "years";
    }
}


function scoreLocal() {
    // TODO consider doing more scoring locally
    // 1.97 is log10(95), the number of possible characters
    if (/^\d+$/.test(newpassword.value)) {
        meter.value = scoreDigits(newpassword.value);
    } else {
        meter.value = ( Math.round(newpassword.value.length * 1.97) );
    }
    scoreTime();
}

function scorePassword() {
  if (newpassword.value.length < 8) {
      scoreLocal();
      return;
  }
  let xhttp = new XMLHttpRequest();
  xhttp.responseType = 'json';
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        let jsonResponse = this.response;
        meter.value = jsonResponse.score
        scoreTime();
    }
  };
  xhttp.open("GET", "/cgi-bin/password-dog/password-dog.cgi?newpassword=" + encodeURIComponent(newpassword.value), true);
  xhttp.send();
}


window.addEventListener('load', (event) => {
	let meter = document.getElementById('strength-meter');
	let newpassword = document.getElementById('newpassword');
  newpassword.addEventListener("input", scorePassword);
});


