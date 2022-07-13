function scoreDigits(password) {
  if (/^\d+$/.test(newpassword)) {
    return;
  }

  var i, years;

  if ( "01234567890".includes(password) || "09876543210".includes(password) ) {
    return 2;
  }

  years = set();
  i = 1940;

  while (i < 2030) {
    years.add(i.toString());
    i += 1;
  }

  if ( years.has(password) ) {
    return 2;
  }

  return password.length;
}


function scoreLocal() {
    // TODO consider doing more scoring locally
    // 1.97 is log10(95), the number of possible characters
    if (/^\d+$/.test(newpassword.value)) {
        meter.value = scoreDigits(newpassword.value);
    } else {
        meter.value = ( Math.round(newpassword.value.length * 1.97) );
    }
}

function scorePassword() {
  if (newpassword.value.length < 8) {
      scoreLocal();
      return;
  }
  var xhttp = new XMLHttpRequest();
  xhttp.responseType = 'json';
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        // var jsonObj = JSON.parse(this.responseText);
        var jsonResponse = this.response;
        // console.log(jsonResponse)
        meter.value = jsonResponse.score
    }
  };
  // xhttp.open("GET", "http://localhost:8080/?newpassword=" + encodeURIComponent(newpassword.value), true);
  xhttp.open("GET", "/cgi-bin/password-dog/password-dog.cgi?newpassword=" + encodeURIComponent(newpassword.value), true);
  xhttp.send();
}
/*
meter = document.getElementById('strength-meter');
newpassword = document.getElementById('newpassword');
meter.addEventListener("change", scorePassword);
*/

class CryptoRandom {
  refreshList() {
    this.numbers = new Uint32Array(256);
    window.crypto.getRandomValues(this.numbers);
    this.decrement = 0;
  }


  constructor() {
    this.refreshList();
  }

  get next() {
    if (this.decrement-- < 1) {
        this.refreshList();
    }
    return this.numbers[this.decrement];
  }

  randbetween(from, to) {
    return from + (this.next % (to + 1 - from));
  }
}

const crand = new CryptoRandom();
/*
for (var i = 0; i < 100; i++) {
  console.log(crand.randbetween(0, 3));
}
*/

seperators = [",", ".", "/", "-", "+"];
function crand_words(wordlist, count) {
    words = [];
    for (let i = 0; i < 3; i++) {
        word = wordlist[crand.randbetween(0, wordlist.length - 1)];
        words.push( word.charAt(0).toUpperCase() + word.slice(1) );
    }
    return words;
}


function gen_pw(count, wordlist) {
  var sep, words;

  words = crand_words(wordlist, count);
  randnum = crand.randbetween(0,9999);
  index = crand.randbetween(0, words.length - 1) ;
  words.splice(index, 0, randnum);
  sep = seperators[crand.randbetween(0, seperators.length - 1)];
  return words.join(sep);
}

function suggest_passwords() {
    suggestions = document.getElementById('pwsuggestions');
    while (suggestions.firstChild) {
        suggestions.removeChild(suggestions.firstChild);
    }
    for (var i = 0; i < 4; i += 1) {
        suggest = gen_pw(3, wordlist);
        var li = document.createElement("li");
        var inputsuggest = document.createElement("input");
        inputsuggest.classList.add("suggestion");
        inputsuggest.setAttribute('size',24);
        inputsuggest.value = suggest;
        inputsuggest.addEventListener("click", copy_pw);
        li.appendChild(inputsuggest);
        suggestions.appendChild(li);
    }

}

window.onload = function() {
	meter = document.getElementById('strength-meter');
	newpassword = document.getElementById('newpassword');
	// newpassword.addEventListener("change", scorePassword);
    newpassword.addEventListener("input", scorePassword);
    suggest_passwords();
}

