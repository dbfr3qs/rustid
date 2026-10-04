// rustid's end session callback: once every front-channel logout iframe has
// loaded (or five seconds have passed), marks the page complete and tells a
// parent page, so a logout page can move on.
(function () {
    "use strict";
    var frames = document.getElementsByTagName("iframe");
    var pending = frames.length;
    var finished = false;

    function done() {
        if (finished) {
            return;
        }
        finished = true;
        document.documentElement.setAttribute("data-signout", "complete");
        if (window.parent !== window) {
            window.parent.postMessage("rustid:signout-complete", "*");
        }
    }

    function loaded() {
        pending -= 1;
        if (pending <= 0) {
            done();
        }
    }

    if (pending === 0) {
        done();
        return;
    }
    for (var i = 0; i < frames.length; i++) {
        frames[i].addEventListener("load", loaded);
    }
    setTimeout(done, 5000);
})();
