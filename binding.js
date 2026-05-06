'use strict'

// require('./package.json') causes bare-pack to include it in the bundle.
// bare's runtime walks up from binding.js's virtual path to find package.json
// and resolve the addon name for require.addon().
require('./package.json')

module.exports = require.addon()
