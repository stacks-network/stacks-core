module.exports = {
  parser: "@typescript-eslint/parser",
  parserOptions: {
    "project": "./tsconfig.json"
  },
  plugins: [
    "@typescript-eslint",
    "prettier"
  ],
  parserOptions: {
    ecmaVersion: 2018,  // Allows for the parsing of modern ECMAScript features
    sourceType: 'module',  // Allows for the use of imports
  },
  extends: [
    "plugin:@typescript-eslint/recommended",
    "prettier/@typescript-eslint",
    "plugin:prettier/recommended"
  ],
  rules: {
    "prettier/prettier": "error",
    "@typescript-eslint/explicit-function-return-type": "off",
    "@typescript-eslint/explicit-member-accessibility": "off",
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/no-use-before-define": "off",
    "@typescript-eslint/camelcase": "off"
  }
}
