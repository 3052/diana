# servers

- <https://refapp.hbbtv.org/dash/test_dashjs_sl3000.html?video=sl3000>
- https://reference.dashif.org/dash.js/nightly/samples/drm/playready.html
- https://sample.pallycon.com/demo/drm-demo/shaka

~~~
mitmproxy --set stream_large_bodies=9m
~~~

even with the above, I cant seem to capture the license request with MitmProxy,
so just use HAR instead:

~~~
mitmproxy -r reference.dashif.org.har
~~~

<https://wikipedia.org/wiki/Replay_attack>

## how to get X-Axdrm-Message?

its in HTML response body:

~~~js
const protData = {
    "com.microsoft.playready": {
        "serverURL": "https://drm-playready-licensing.axtest.net/AcquireLicense",
        "httpRequestHeaders": {
            "X-AxDRM-Message": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJz..."
        }
    }
};
~~~
