### msbc


*my* [sing-box](https://github.com/SagerNet/sing-box) configurator.

this program fetches a list of urls encoded in base64 from a remote endpoint defined by the environment variable `SERVER_LIST_URL`, rewrites it in the format of sing-box outbounds if the protocol of the url is `trojan`, and automatically generates tag-based `selector` and `urltest` outbounds which are then appended to selector outbounds defined in `./config/selectors.scheme.json`. the program exports to the default sing-box config directory `/etc/sing-box` along with any other config files found under `./config`.

the included config files are heavily customized and very specific to my own use case which will *not* work for your local network. it is **strongly encouraged** that you [write your own sing-box config](https://sing-box.sagernet.org/configuration/). understanding the tool you use gives greater flexibility and is a necessary part of the learning process, in my very humble opinion.