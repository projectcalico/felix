# VPP support for Calico.

### What is VPP?
VPP is a high throughput, modular, userspace network data plane.
For more information about VPP, pease see the project's homepage at [http://fd.io](http://fd.io)

### Using VPP with Calico.
This branch of felix supports 'pluggable devices', allowing felix to talk to other 'backends' rather than just the linux kernel for networking.
In our case, we have written a VPP device plugin.

To use the VPP device plugin, ensure the dependencies from the section below are met, then simply change the following in ```calico/felix/config.py```

From:

```
self.add_parameter("DevicesPlugin",
                   "Which devices plugin to use.",
                   "default")
```

To:
```
self.add_parameter("DevicesPlugin",
                   "Which devices plugin to use.",
                   "vpp")

```

Then compile felix as normal.
Felix will then expect to import the VPP Python API module at runtime and will expect a running instance of VPP on the host to communicate with.
(Again, see dependencies below).


### Dependencies
To run the VPP version of felix, you must have the following on the local machine.

* VPP compiled and running. See [https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Building](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Building)

* The VPP Python API bindings compiled and installed. See [https://wiki.fd.io/view/VPP/Python_API](https://wiki.fd.io/view/VPP/Python_API)

* VPP Started on the host. ```$vppctl sh int``` Should return data and not error/hang.

* Regular Calico/Felix dependancies met from the calico documentation.

### Project Status
This code should be considered alpha / PoC grade. We are working on known issues and would not recommend running this in production.


### Demo's
* Calico CNI integration for Kubernetes. Using this VPP plugin for networking: [https://www.youtube.com/watch?v=1-UDQNLZTQ0](https://www.youtube.com/watch?v=1-UDQNLZTQ0)

* Calico calicoctl docker integration. Using IPv6 connectivity: [https://www.youtube.com/watch?v=SgRmmvZwQvw](https://www.youtube.com/watch?v=SgRmmvZwQvw)
