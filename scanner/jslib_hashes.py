"""SHA-256 fingerprints of known-vulnerable JavaScript library releases.

Built by hashing the actual minified dist files downloaded from jsDelivr.
Only the hashes are stored here — no file contents, no invented data.

A byte-identical match means the site serves that exact release, which
has publicly documented vulnerabilities (see VULNERABLE_JS in checks.py
for the fixed versions, FIXED_IN_EXACT for releases whose CVE ranges
have patch-level exceptions). Findings are worded as "publicly known
vulnerabilities" — no CVE numbers are invented.

Covered: jquery, bootstrap, angularjs, lodash, moment, react-dom,
vue (2.x), angular (@angular/core, UMD era).
"""

VULN_JS_HASHES = {
    "05b85d96f41fff14d8f608dad03ab71e2c1017c2da0914d7c59291bad7a54f8e": ("jquery", "2.2.4"),
    "0925e8ad7bd971391a8b1e98be8e87a6971919eb5b60c196485941c3c1df089a": ("jquery", "3.4.1"),
    "0b86e93ae07e8c3ee975204e6dbd53cbbce457b8f5e9c2397c4312285d488991": ("bootstrap", "4.3.0"),
    "160a426ff2894252cd7cebbdd6d6b7da8fcd319c65b70468f10b6690c45d02ef": ("jquery", "3.3.1"),
    "53964478a7c634e8dad34ecc303dd8048d00dce4993906de1bacf67f663486ef": ("bootstrap", "3.3.7"),
    "55e35a1415438685f71fe809dfb0e94ff9d3b994dd8d8ae8f7206bb878d59a84": ("lodash", "4.17.15"),
    "668b046d12db350ccba6728890476b3efee53b2f42dbb84743e5e9f1ae0cc404": ("jquery", "1.12.4"),
    "6f936f9af51ccabd30a4138b9cd6da587e73290022be18fcc8c6217d712e9900": ("angularjs", "1.7.9"),
    "73de4254959530e4d1d9bec586379184f96b4953dacf9cd5e5e2bdd7bfeceef7": ("moment", "2.29.1"),
    "87083882cc6015984eb0411a99d3981817f5dc5c90ba24f0940420c5548d82de": ("jquery", "3.2.1"),
    "b24f4e645db81ea79bb26791e2c282c5e31ab68900ecab482b88473bad2a9b9e": ("angularjs", "1.6.10"),
    "babfd8947314f7a3311c4b32ddf1c6b336476acecdcc7e114250f8b4356f161c": ("lodash", "4.17.20"),
    "e22419e8154be2a34a950dbb4c4c448413751c53ef02f00c6c56af28aa2c4964": ("moment", "2.24.0"),
    "eb795deda8983fa5310627c9584cf3f3b95d272567113500059018b3941cb267": ("bootstrap", "4.2.1"),
    # --- react-dom: GHSA-mvjj-gqq2-p4hw (XSS). Patch-level exceptions
    # (16.0.1, 16.1.2, 16.2.1, 16.3.3 are fixed) rule out a "below" check,
    # so these exact vulnerable releases are fingerprinted instead.
    "0dcb93a5c7859e1fa909ffe239b591ec329bfea81bf5e059ecb1b6f7e1ca7058": ("react-dom", "16.0.0"),
    "4b589e536a85f6707a1f2e4018c1425ed6fe73e8ed4346452ee24949f28f86b9": ("react-dom", "16.1.0"),
    "77485f185036d3da0d6449c427c64928b97df99305788ac80221736924916395": ("react-dom", "16.1.1"),
    "f61ac9c43e0842c58774da732e424a606898fd211914925252ac9e64f34a77c8": ("react-dom", "16.2.0"),
    "a15dd3609e69da9d2a5c0dae4f731ea6eec529ad191f4a4b5b6840e5d9beed5e": ("react-dom", "16.3.0"),
    "f66fd73f63a0e04d8c8afbc4af8d6d9547e34e45b58e33bbbac91b417ee03114": ("react-dom", "16.3.1"),
    "96b84a25a5984c39eab253b08ff07c7f3e9ba9e848480eb8c284112ea04a0db0": ("react-dom", "16.3.2"),
    "aaceabb9d1a1c4f32fd95ab6432621fc34e7d3955ef31527e9698171abf5e998": ("react-dom", "16.4.0"),
    "cbba3f6f7e49ca36f5f7027ffc65239bce1b2e5f989660c69a7c29819bf337ee": ("react-dom", "16.4.1"),
    # --- vue 2.x: GHSA-5j4c-8p2g-v4jx (ReDoS, all of 2.x, fixed in 3.x)
    "9174c425c445377df4562ad9165ea08fdf9433a808296d7de5f619791df10e17": ("vue", "2.6.14"),
    "d601f229247b261d18181988f7337b3f652165187f3c22a109821a50ea96a0f9": ("vue", "2.7.14"),
    "3c1d4b0c549e8de9d4a9bafb12ab70b6a1ac747d07293b98c5b25b6632999afd": ("vue", "2.7.16"),
    # --- @angular/core UMD builds: GHSA-c75v-2vq8-878f (XSS pre-10.2.5,
    # and in 11.0.0-11.0.4)
    "1663a489eda8bec4b42132036735b4415cc60e407d88e1bd6c6e4034a8c099f6": ("angular", "10.2.4"),
    "ea69cc02526f075b51f8f878b073e82d4d90d6e2357eec8eb755492a4ee70155": ("angular", "11.0.4"),
}
