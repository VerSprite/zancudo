const lib = require('./test/require_test/lib.js');

function analyzePayload(payload) {
    const a = 1;
    const b = 2;
    const result = lib.add(a, b);
    console.log(`Test require: ${a} + ${b} = ${result}`);
    if (result !== 3) {
        throw new Error("Require test failed!");
    }
    return "OK";
}

module.exports = {
    analyzePayload: analyzePayload
};