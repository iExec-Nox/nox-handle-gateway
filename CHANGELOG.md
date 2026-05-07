# Changelog

## [0.6.0](https://github.com/iExec-Nox/nox-handle-gateway/compare/v0.5.0...v0.6.0) (2026-05-07)


### Features

* add rate limit on concurrent S3 operations ([#66](https://github.com/iExec-Nox/nox-handle-gateway/issues/66)) ([d9a8db8](https://github.com/iExec-Nox/nox-handle-gateway/commit/d9a8db8e40bd044722bee14f1bad2fbd3a3b5e3d))
* multi-chain RPC support with per-chain configuration ([#70](https://github.com/iExec-Nox/nox-handle-gateway/issues/70)) ([1a0e1d8](https://github.com/iExec-Nox/nox-handle-gateway/commit/1a0e1d8b26d3a29e4b45c849f7ade5ffb730d166))
* parallelize handle status HEAD checks and cap oversized batches ([#72](https://github.com/iExec-Nox/nox-handle-gateway/issues/72)) ([71879e8](https://github.com/iExec-Nox/nox-handle-gateway/commit/71879e8f42e71d0c633fdca335041c2f4f74890c))
* support multiple S3 buckets with chain ID routing ([#67](https://github.com/iExec-Nox/nox-handle-gateway/issues/67)) ([4251c42](https://github.com/iExec-Nox/nox-handle-gateway/commit/4251c428c6f9fc1baff6ade9214444bd634c18ac))
* use join_all to perform concurrent operations on S3 ([#64](https://github.com/iExec-Nox/nox-handle-gateway/issues/64)) ([16efbe5](https://github.com/iExec-Nox/nox-handle-gateway/commit/16efbe51f574334fe08bc14d83b35761fee5c64f))

## [0.5.0](https://github.com/iExec-Nox/nox-handle-gateway/compare/v0.4.0...v0.5.0) (2026-03-27)


### Features

* add AUTHORIZATION header based on EIP-712 on compute REST endpoints ([#39](https://github.com/iExec-Nox/nox-handle-gateway/issues/39)) ([51efa46](https://github.com/iExec-Nox/nox-handle-gateway/commit/51efa465735e596afac9d8013f2c937804e53e0e))
* add compute handles retrieval ([#26](https://github.com/iExec-Nox/nox-handle-gateway/issues/26)) ([5bf408d](https://github.com/iExec-Nox/nox-handle-gateway/commit/5bf408dd074dd67d69445e52a58519501e77e821))
* add compute results publishing ([#24](https://github.com/iExec-Nox/nox-handle-gateway/issues/24)) ([0836a8a](https://github.com/iExec-Nox/nox-handle-gateway/commit/0836a8ad3e990c0cd877ca001e5549bef228a208))
* add docker release gha ([#63](https://github.com/iExec-Nox/nox-handle-gateway/issues/63)) ([0530eef](https://github.com/iExec-Nox/nox-handle-gateway/commit/0530eeff1dd277cc13ff6eeb969fead1ff4a9397))
* add EIP712 signature to GET /handle/status response ([#52](https://github.com/iExec-Nox/nox-handle-gateway/issues/52)) ([dd546c2](https://github.com/iExec-Nox/nox-handle-gateway/commit/dd546c2a95060c1994661ae1c269f2dfbf57b453))
* add EIP712 signature to GET /v0/secrets/{handle} response ([#57](https://github.com/iExec-Nox/nox-handle-gateway/issues/57)) ([575c92e](https://github.com/iExec-Nox/nox-handle-gateway/commit/575c92e6d9c1271aee9517ecb5e68783a474e914))
* add endpoint to fetch handle encrypted material ([#13](https://github.com/iExec-Nox/nox-handle-gateway/issues/13)) ([72cbe41](https://github.com/iExec-Nox/nox-handle-gateway/commit/72cbe41a7bd61fc92b34585bc9802aa79aeaec09))
* add GET /v0/public/:handle public decryption endpoint ([#42](https://github.com/iExec-Nox/nox-handle-gateway/issues/42)) ([1738bae](https://github.com/iExec-Nox/nox-handle-gateway/commit/1738baeb2df6799d98b4356608e9d0ff5da9e577))
* add optional salt query parameter for EIP712 signatures ([#59](https://github.com/iExec-Nox/nox-handle-gateway/issues/59)) ([3fa86d4](https://github.com/iExec-Nox/nox-handle-gateway/commit/3fa86d496d95e1183ffbdecce7875aaf76e110e1))
* add PostgreSQL repository for storage ([#9](https://github.com/iExec-Nox/nox-handle-gateway/issues/9)) ([c49f643](https://github.com/iExec-Nox/nox-handle-gateway/commit/c49f643dc897a3f63c977020540d02326ba444bc))
* add Prometheus metrics ([#7](https://github.com/iExec-Nox/nox-handle-gateway/issues/7)) ([85ac17d](https://github.com/iExec-Nox/nox-handle-gateway/commit/85ac17da6f839a51f4646cbfb3108588a2b92cd5))
* add signature verification for KMS delegate response ([#20](https://github.com/iExec-Nox/nox-handle-gateway/issues/20)) ([07d139b](https://github.com/iExec-Nox/nox-handle-gateway/commit/07d139bc9b8326ce253ffe5ea29cf7a45d3df3aa))
* enrich S3 handle metadata and add idempotent compute result publishing ([#51](https://github.com/iExec-Nox/nox-handle-gateway/issues/51)) ([b6b0bb5](https://github.com/iExec-Nox/nox-handle-gateway/commit/b6b0bb590ec4a37c9618194cbc604d3439da5b02))
* expose endpoint to check ciphertext existence for handles ([#40](https://github.com/iExec-Nox/nox-handle-gateway/issues/40)) ([98a8f12](https://github.com/iExec-Nox/nox-handle-gateway/commit/98a8f120675510c70c7cd744a23b563e14d44691))
* fetch KMS public key at startup ([#8](https://github.com/iExec-Nox/nox-handle-gateway/issues/8)) ([543e19c](https://github.com/iExec-Nox/nox-handle-gateway/commit/543e19c776d20a29f47e999d2f34dea5296a19ce))
* fetch KMS public key on-chain ([#28](https://github.com/iExec-Nox/nox-handle-gateway/issues/28)) ([c549971](https://github.com/iExec-Nox/nox-handle-gateway/commit/c54997171aeee4bcb6f9cf3339d704b9ca10a6a8))
* implement ACL on-chain verification ([#21](https://github.com/iExec-Nox/nox-handle-gateway/issues/21)) ([9f109fe](https://github.com/iExec-Nox/nox-handle-gateway/commit/9f109fe1cc9cbe529064febdd38c7a1fcd211526))
* implement authorization header for KMS delegate request ([#19](https://github.com/iExec-Nox/nox-handle-gateway/issues/19)) ([d07aaff](https://github.com/iExec-Nox/nox-handle-gateway/commit/d07aaffc351fc736640895602f14fdbf1c3be1d2))
* implement ECIES encryption ([#10](https://github.com/iExec-Nox/nox-handle-gateway/issues/10)) ([b57130e](https://github.com/iExec-Nox/nox-handle-gateway/commit/b57130e61d6fb0ad8c8c465f8511f03775beb477))
* implement ERC-1271 signature verification ([#37](https://github.com/iExec-Nox/nox-handle-gateway/issues/37)) ([cbf5e57](https://github.com/iExec-Nox/nox-handle-gateway/commit/cbf5e572565add7d620c689345372be3b2ef6a9c))
* implement handle creation endpoint ([#5](https://github.com/iExec-Nox/nox-handle-gateway/issues/5)) ([93335ac](https://github.com/iExec-Nox/nox-handle-gateway/commit/93335aca8f5adf818ecfe5b681c0ccc07b930b37))
* implement handle request input validation ([#14](https://github.com/iExec-Nox/nox-handle-gateway/issues/14)) ([477dbe8](https://github.com/iExec-Nox/nox-handle-gateway/commit/477dbe869e8673362ded4dad88c05fa545aaf40e))
* implement input proof computation ([#6](https://github.com/iExec-Nox/nox-handle-gateway/issues/6)) ([2e09ae7](https://github.com/iExec-Nox/nox-handle-gateway/commit/2e09ae746ca8d2dcf0e817196b764f0461766b50))
* implement new Handle struct ([#45](https://github.com/iExec-Nox/nox-handle-gateway/issues/45)) ([1468ea9](https://github.com/iExec-Nox/nox-handle-gateway/commit/1468ea9422969242cdd3de51bf6ccf403562e4de))
* implement optional endpoint URL and object lock settings in S3 configuration ([#35](https://github.com/iExec-Nox/nox-handle-gateway/issues/35)) ([81f8a1f](https://github.com/iExec-Nox/nox-handle-gateway/commit/81f8a1f6f2c61e611ba6b570ad744848c7e43697))
* implement persistent wallet ([#17](https://github.com/iExec-Nox/nox-handle-gateway/issues/17)) ([0f9dc2c](https://github.com/iExec-Nox/nox-handle-gateway/commit/0f9dc2c70ae6e15ef38222bc1c69048200b98da0))
* initialize project ([#1](https://github.com/iExec-Nox/nox-handle-gateway/issues/1)) ([0d6d97f](https://github.com/iExec-Nox/nox-handle-gateway/commit/0d6d97fa3243a6c9a33b0e4f82fc2312ae203080))
* initialize server ([#4](https://github.com/iExec-Nox/nox-handle-gateway/issues/4)) ([ed661ae](https://github.com/iExec-Nox/nox-handle-gateway/commit/ed661aebc928bc0fc05ec1571836dcef076c24f5))
* inject signer key into env variable ([#33](https://github.com/iExec-Nox/nox-handle-gateway/issues/33)) ([3abae20](https://github.com/iExec-Nox/nox-handle-gateway/commit/3abae2064d6cc91fc8b38ac389184b56997856d3))
* limit HTTP metrics to the defined endpoints ([#54](https://github.com/iExec-Nox/nox-handle-gateway/issues/54)) ([8b1362a](https://github.com/iExec-Nox/nox-handle-gateway/commit/8b1362ae575f8e8ef7bbc31f2ab319cfe0f94450))
* replace PostgreSQL by S3 storage for handle management ([#31](https://github.com/iExec-Nox/nox-handle-gateway/issues/31)) ([24067f8](https://github.com/iExec-Nox/nox-handle-gateway/commit/24067f897dc03c8872e86df4d551a1eaa5b7683c))
* sign Handle Gateway responses with EIP-712 on /v0/compute endpoint ([#41](https://github.com/iExec-Nox/nox-handle-gateway/issues/41)) ([af6190a](https://github.com/iExec-Nox/nox-handle-gateway/commit/af6190aa1d25259b67d80e668fc3201a4140ef89))
* update InputProof to HandleProof ([#16](https://github.com/iExec-Nox/nox-handle-gateway/issues/16)) ([1b3bd2c](https://github.com/iExec-Nox/nox-handle-gateway/commit/1b3bd2cb3615b41aa652ea3ae7e4cee8e18dc169))
* verify KMS public key response ([#18](https://github.com/iExec-Nox/nox-handle-gateway/issues/18)) ([df856ae](https://github.com/iExec-Nox/nox-handle-gateway/commit/df856ae9d9050065308006c4826b15b5cae70bcc))


### Bug Fixes

* add back handle field on DescryptionProof ([#47](https://github.com/iExec-Nox/nox-handle-gateway/issues/47)) ([f09d1f0](https://github.com/iExec-Nox/nox-handle-gateway/commit/f09d1f05a19337ee189fccf2511a7c2ab9de080e))
* cors add content type header ([#46](https://github.com/iExec-Nox/nox-handle-gateway/issues/46)) ([9a95e5c](https://github.com/iExec-Nox/nox-handle-gateway/commit/9a95e5c240bf94b35c5bb761874b0d6cc14f4350))
* enforce strict size check on encoded inputs ([#53](https://github.com/iExec-Nox/nox-handle-gateway/issues/53)) ([a92b4c1](https://github.com/iExec-Nox/nox-handle-gateway/commit/a92b4c1e79a7bbbbb97a7ffd3eb84d7d1edb88f6))
* fallback DataAccessAuthorization signature verification to ERC-1271 ([#55](https://github.com/iExec-Nox/nox-handle-gateway/issues/55)) ([b367b09](https://github.com/iExec-Nox/nox-handle-gateway/commit/b367b099aae3833f09844ace4565c2d9284cbfc6))
* fix CORS Access-Control-Allow-Headers wildcard not covering Authorization ([#38](https://github.com/iExec-Nox/nox-handle-gateway/issues/38)) ([46a6767](https://github.com/iExec-Nox/nox-handle-gateway/commit/46a6767f5135cbb145933e016bf17595ff43d723))
* improve object lock configuration handling in S3 repository ([#36](https://github.com/iExec-Nox/nox-handle-gateway/issues/36)) ([1879001](https://github.com/iExec-Nox/nox-handle-gateway/commit/1879001eddbde184189a14164cad4f593dd185dc))
* limit DataAccessAuthorization token validity window to 1h ([#49](https://github.com/iExec-Nox/nox-handle-gateway/issues/49)) ([7e66aec](https://github.com/iExec-Nox/nox-handle-gateway/commit/7e66aecdded497dbce62128613019169d8845e53))
* preserve handles order when fetching operands ([#30](https://github.com/iExec-Nox/nox-handle-gateway/issues/30)) ([7202902](https://github.com/iExec-Nox/nox-handle-gateway/commit/7202902e9519c7e50add71ff27a82e5770746c83))
* update VERSIONED_PATHS format to use path parameters correctly ([#58](https://github.com/iExec-Nox/nox-handle-gateway/issues/58)) ([23494fd](https://github.com/iExec-Nox/nox-handle-gateway/commit/23494fdb02bbce11a0bc787ad03f9e39b9b93f4f))
