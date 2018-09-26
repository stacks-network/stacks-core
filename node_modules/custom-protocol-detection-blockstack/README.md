# Custom Protocol Detection in Browser
Detect whether a custom protocol is available in browser (FF, Chrome, IE8, IE9, IE10, IE11, and Edge)

The implementation is different from one browser to another, sometimes depend on which OS you are. Most of them are hacks, meaning that the solution is not the prettiest.

* Firefox: try to open the handler in a hidden iframe and catch exception if the custom protocol is not available.
* Chrome: using window onBlur to detect whether the focus is stolen from the browser. When the focus is stolen, it assumes that the custom protocol launches external app and therefore it exists.
* IEs and Edge in Win 8/Win 10: the cleanest solution. IEs and Edge in Windows 8 and Windows 10 does provide an API to check the existence of custom protocol handlers.
* Other IEs: various different implementation. Worth to notice that even the same IE version might have a different behavior (I suspect due to different commit number). It means that for these IEs, the implementation is the least reliable.
* Other browsers (like Safari): Call the unsupported protocol callback (if provided) otherwise call the fail callback

# Usage

```JavaScript
import protocolCheck from 'custom-protocol-detection'
const uri = 'customprotocol:datahere'
protocolCheck(uri,
  () => {
    console.log('This browser does not support the protocol')
  },
  () => {
    console.log('This browser supports the protocol')
  },
  () => {
    console.log('This browser does not provide a method to detect protocol support')
  })
```

# Known Issues

* In some protocol such as "mailto:", IE seems to trigger the fail callback while continuing on opening the protocol just fine (tested in IE11/Win 10). This issue doesn't occur with a custom protocol.
* Edge, in contrast, never fail anything as it will just offer users to find an app in Windows Store to open an unknown protocol.
