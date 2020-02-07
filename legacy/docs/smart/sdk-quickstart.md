---
layout: core
permalink: /:collection/:path.html
---
# Quickstart for the SDK
{:.no_toc}

You can use the software developer kit (SDK) to develop, test, and deploy Clarity smart contracts. The SDK goes beyond the basic test environment to allow for development of Javascript or TypeScript clients that call upon Clarity contracts.

* TOC
{:toc}

<div class="uk-card uk-card-default uk-card-body">
<h5>Clarity is in pre-release</h5>
<p>Clarity, its accompanying toolset, and the SDK are in pre-release. If you encounter issues with or have feature requests regarding Clarity, please create an issue on the <a href='https://github.com/blockstack/blockstack-core/issues' target='_blank'>blockstack/blockstack-core</a> repository. To read previous or join ongoing discussions about smart contracts in general and Clarity in particular, visit the <strong><a href='https://forum.blockstack.org/c/clarity' target='_blank'>Smart Contracts</a></strong> topic in the Blockstack Forum.
</p>
</div>

## About this tutorial and the prerequisites you need

{% include note.html content="This tutorial was written on macOS High Sierra 10.13.4. If you use a Windows or Linux system, you can still follow along. However, you will need to \"translate\" appropriately for your operating system." %}

For this tutorial, you will use  `npm` to manage dependencies and scripts. The tutorial relies on the `npm` dependency manager. Before you begin, verify you have installed `npm` using the `which` command to verify.

```bash
$ which npm
/usr/local/bin/npm
```

If you don't find `npm` in your system, [install
it](https://www.npmjs.com/get-npm).

You use `npm` to install Yeoman. Yeoman is a generic scaffolding system that
helps users rapidly start new projects and streamline the maintenance of
existing projects. Verify you have installed `yo` using the `which` command. 


```
$ which yo
/usr/local/bin/yo
```

If you don't have Yeoman, you can install it with the `npm install -g yo` command.

## Task 1: Generate an initial Clarity project

The SDK uses Yeoman to generate a project scaffold &mdash; an initial set of directories and files.   

1. Create a new directory for your project.

    ```sh
    mkdir hello-clarity-sdk
    ```
2. Change into your new project directory.

    ```sh
    cd hello-clarity-sdk
    ```

3. Use the `npm` command to initialize a Clarity project.

    ```sh
    npm init yo clarity-dev
    npx: installed 15 in 1.892s
      create package.json
      create .vscode/extensions.json
    ...
    Project created at /private/tmp/hello-clarity-sdk
    ✔ create-yo ok!
    ```

    Depending on your connection speed, it may take time to construct the scaffolding.

## Task 2: Investigate the generated project 
   
Your project should contain three directories:

 | Directory |Description  |
 |---|---|
 | `contracts` | Contains `.clar` files (Clarity contract files) here.  |
 | `test` | Contains files for testing your application. |
 | `node_modules` | Contains packages the project depends on. Added by `npm`. |
 
The `contracts` directory contains a single file in `sample/hello-world.clar` file.

```cl
(define (say-hi)
   "hello world")

(define (echo-number (val int))
   val)
```

The contract exposes 2 rudimentary functions. The **say-hi** returns a `hello world` string. The **increment-number**: echos  `val`. 

The project also includes `tests/hello-world.ts` file. The test is written in Typescript. You can also write tests in Javascript.

{% highlight cl linenos %}
import { Client, Provider, ProviderRegistry, Result } from "@blockstack/clarity";
import { assert } from "chai";

describe("hello world contract test suite", () => {
  let helloWorldClient: Client;
  let provider: Provider;

  before(async () => {
    provider = await ProviderRegistry.createProvider();
    helloWorldClient = new Client("hello-world", "sample/hello-world", provider);
  });

  it("should have a valid syntax", async () => {
    await helloWorldClient.checkContract();
  });

  describe("deploying an instance of the contract", () => {
    before(async () => {
      await helloWorldClient.deployContract();
    });

    it("should return 'hello world'", async () => {
      const query = helloWorldClient.createQuery({ method: { name: "say-hi", args: [] } });
      const receipt = await helloWorldClient.submitQuery(query);
      const result = Result.unwrap(receipt);
      const parsedResult = Buffer.from(result.replace("0x", ""), "hex").toString();
      assert.equal(parsedResult, "hello world");
    });

    it("should echo number", async () => {
      const query = helloWorldClient.createQuery({
        method: { name: "echo-number", args: ["123"] }
      });
      const receipt = await helloWorldClient.submitQuery(query);
      const result = Result.unwrap(receipt);
      assert.equal(result, "123");
    });
  });

  after(async () => {
    await provider.close();
  });
});
{% endhighlight %}

The `hello-world.ts` test file is a client that runs the `hello-world.clar` contract. Tests are critical for smart contracts as they are intended to manipulate assets and their ownership. These manipulations are irreversible within a blockchain. As you create a contracts, you should not be surprise if you end up spending more time and having more code in your `tests` than in your `contracts` directory. The `tests/hello-world.ts` file in the scaffold has the following content:

The first part of the test (lines 1 -10) sets up the test environment. It defines a Clarity `provider` and launches it (line 9). The Client instance contains a contract name and the path to the sample code. This test also checks the client (line 14) and then launches it (line 19), this is equivalent to running `clarity-cli check` with the command line. The remaining test code exercises the contract. Try running this test.


```sh
npm run test

> hello-clarity-sdk@0.0.0 test /private/tmp/hello-clarity-sdk
> mocha



  hello world contract test suite
    ✓ should have a valid syntax
    deploying an instance of the contract
      ✓ should print hello world message
      ✓ should echo number


  3 passing (182ms)
```

In the next section, try your hand at expanding the `hello-world.clar` program.

## Task 3: Try to expand the contract

In this task, you are challenged to expand the contents of the `contracts/hello-world.clar` file. Use your favorite editor and open the `contracts/hello-world.clar` file. If you use Visual Studio Code, you can install the Blockstack Clarity extension. The extension provides `syntax coloration` and some `autocompletion`. 

Edit the `hello-world.clar` file.

```cl
;; Functions

(define (hello-world)
   "hello world")

(define (echo-number (val int))
   val)
```

Use the `+` function to create a `increment-number-by-10` function.  
  
<div class="uk-inline">
<button class="uk-button uk-button-primary" enter="button">ANSWER</button>
<div uk-dropdown>
<pre>
;; Functions

(define (say-hi)
"hello world")

(define (increment-number (number int))
(+ 1 number))

(define (increment-number-by-10 (number int))
(+ 10 number))
</pre>
</div>
</div>

Use the `+` and `-` function to create a `decrement-number` user-defined method. 

<div class="uk-inline">
    <button class="uk-button uk-button-primary" enter="button">ANSWER</button>
    <div uk-dropdown>
    <pre>
    ;; Functions

   (define (say-hi)
   "hello world")

   (define (increment-number (number int))
   (+ 1 number))

   (define (increment-number-by-10 (number int))
   (+ 10 number))

   (define (decrement-number (number int))
   (- number 1))
    </pre>
   </div>
</div>

Finally, try adding a `counter` variable and be sure to store it. Increment `counter` in your code` and add a `get-counter` funtion to return the result. Here is a hint, you can add a `var` to a contract by adding the following line (before the function): 

```cl
;; Storage

(define-data-var internal-value int 0)
```

<div class="uk-inline">
<button class="uk-button uk-button-primary" enter="button">ANSWER</button>
<div uk-dropdown>
<pre>
;; Storage

(define-data-var counter int 0)

;; Functions

(define (say-hi)
"hello world")

(define (increment-number (number int))
(+ 1 number))

(define (increment-number-by-10 (number int))
(+ 10 number))

(define (decrement-number (number int))
(- number 1))

(define (increment-counter)
  (set-var! counter (+ 1 counter)))

(define (get-counter)
  (counter))

</pre>
</div>
</div>

To review other, longer sample programs visit the <a href="https://github.com/blockstack/clarity-js-sdk/tree/master/packages/clarity-tutorials" target="_blank">clarity-js-sdk</a> repository.