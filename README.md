<img src="/.github/assets/bare-wasm3-logo.svg" width="400px" align="right"></img>

### bare-wasm3

A [Bare](https://github.com/holepunchto/bare) addon that ships a `WebAssembly`
implementation backed by [wasm3](https://github.com/wasm3/wasm3), patched to be `wasm-bindgen` compatible.

## Usage

Inside a Bare worklet, install the polyfill **before** any code that touches
`WebAssembly`:

```js
require('bare-wasm3/global')

const mod = new globalThis.WebAssembly.Module(wasmBytes)
const inst = new globalThis.WebAssembly.Instance(mod, imports)
```

You can also use the lower-level API directly:

```js
const { Module, Instance } = require('bare-wasm3')
```

## Build

Requires macOS with Xcode, [bun](https://bun.sh), and `quilt` (for applying
the wasm3 patches).

```sh
# install dependencies
brew install quilt
bun install

# build all targets
bun run build
# or build a single target
bun run build:ios-arm64-simulator
```

## License

See [LICENSE](./LICENSE).
