# NodeJS Web 开发第五版（五）

> 原文：[`zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA`](https://zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

单元测试和功能测试

单元测试已成为良好软件开发实践的主要部分。这是一种通过测试源代码的各个单元来确保它们正常运行的方法。每个单元在理论上都是应用程序中最小的可测试部分。

在单元测试中，每个单元都是单独测试的，尽可能地将被测试的单元与应用程序的其他部分隔离开来。如果测试失败，你希望它是由于你的代码中的错误而不是你的代码碰巧使用的包中的错误。一个常见的技术是使用模拟对象或模拟数据来将应用程序的各个部分相互隔离开来。

另一方面，功能测试并不试图测试单独的组件。相反，它测试整个系统。一般来说，单元测试由开发团队执行，而功能测试由**质量保证**（**QA**）或**质量工程**（**QE**）团队执行。这两种测试模型都需要完全认证一个应用程序。一个类比可能是，单元测试类似于确保句子中的每个单词都拼写正确，而功能测试确保包含该句子的段落具有良好的结构。

写一本书不仅需要确保单词拼写正确，还需要确保单词串成有用的语法正确的句子和传达预期含义的章节。同样，一个成功的软件应用程序需要远不止确保每个“单元”行为正确。整个系统是否执行了预期的操作？

在本章中，我们将涵盖以下主题：

+   断言作为软件测试的基础

+   Mocha 单元测试框架和 Chai 断言库

+   使用测试来查找错误并修复错误

+   使用 Docker 管理测试基础设施

+   测试 REST 后端服务

+   在真实的 Web 浏览器中使用 Puppeteer 进行 UI 功能测试

+   使用元素 ID 属性改进 UI 可测试性

在本章结束时，你将知道如何使用 Mocha，以及如何为直接调用的测试代码和通过 REST 服务访问的测试代码编写测试用例。你还将学会如何使用 Docker Compose 来管理测试基础设施，无论是在你的笔记本电脑上还是在来自第十二章的 AWS EC2 Swarm 基础设施上，*使用 Terraform 部署 Docker Swarm 到 AWS EC2*。

这是一个需要覆盖的大片领土，所以让我们开始吧。

# 第十七章：Assert - 测试方法学的基础

Node.js 有一个有用的内置测试工具，称为`assert`模块。其功能类似于其他语言中的 assert 库。换句话说，它是一组用于测试条件的函数，如果条件表明存在错误，`assert`函数会抛出异常。虽然它并不是完整的测试框架，但仍然可以用于一定程度的测试。

在其最简单的形式中，测试套件是一系列`assert`调用，用于验证被测试对象的行为。例如，一个测试套件可以实例化用户认证服务，然后进行 API 调用并使用`assert`方法验证结果，然后进行另一个 API 调用来验证其结果，依此类推。

考虑以下代码片段，你可以将其保存在名为`deleteFile.mjs`的文件中：

```

The first thing to notice is this contains several layers of asynchronous callback functions. This presents a couple of challenges:  

*   Capturing errors from deep inside a callback
*   Detecting conditions where the callbacks are never called

The following is an example of using `assert` for testing. Create a file named `test-deleteFile.mjs` containing the following:

```

这就是所谓的负面测试场景，它测试的是请求删除一个不存在的文件是否会抛出正确的错误。如果要删除的文件不存在，`deleteFile`函数会抛出一个包含*不存在*文本的错误。这个测试确保正确的错误被抛出，如果抛出了错误的错误，或者没有抛出错误，测试将失败。

如果您正在寻找一种快速测试的方法，`assert`模块在这种用法下可能很有用。每个测试用例都会调用一个函数，然后使用一个或多个`assert`语句来测试结果。在这种情况下，`assert`语句首先确保`err`具有某种值，然后确保该值是`Error`实例，最后确保`message`属性具有预期的文本。如果运行并且没有消息被打印，那么测试通过。但是如果`deleteFile`回调从未被调用会发生什么？这个测试用例会捕获到这个错误吗？

```

No news is good news, meaning it ran without messages and therefore the test passed.

The `assert` module is used by many of the test frameworks as a core tool for writing test cases. What the test frameworks do is create a familiar test suite and test case structure to encapsulate your test code, plus create a context in which a series of test cases are robustly executed.

For example, we asked about the error of the callback function never being called. Test frameworks usually have a timeout so that if no result of any kind is supplied within a set number of milliseconds, then the test case is considered an error.

There are many styles of assertion libraries available in Node.js. Later in this chapter, we'll use the Chai assertion library ([`chaijs.com/`](http://chaijs.com/)), which gives you a choice between three different assertion styles (should, expect, and assert).

# Testing a Notes model

Let's start our unit testing journey with the data models we wrote for the Notes application. Because this is unit testing, the models should be tested separately from the rest of the Notes application.

In the case of most of the Notes models, isolating their dependencies implies creating a mock database. Are you going to test the data model or the underlying database? Mocking out a database means creating a fake database implementation, which does not look like a productive use of our time. You can argue that testing a data model is really about testing the interaction between your code and the database. Since mocking out the database means not testing that interaction, we should test our code against the database engine in order to validate that interaction.

With that line of reasoning in mind, we'll skip mocking out the database, and instead run the tests against a database containing test data. To simplify launching the test database, we'll use Docker to start and stop a version of the Notes application stack that's set up for testing.

Let's start by setting up the tools.

## Mocha and Chai­ – the chosen test tools

If you haven't already done so, duplicate the source tree so that you can use it in this chapter. For example, if you had a directory named `chap12`, create one named `chap13` containing everything from `chap12` to `chap13`.

In the `notes` directory, create a new directory named `test`.

Mocha ([`mochajs.org/`](http://mochajs.org/)) is one of many test frameworks available for Node.js. As you'll see shortly, it helps us write test cases and test suites, and it provides a test results reporting mechanism. It was chosen over the alternatives because it supports Promises. It fits very well with the Chai assertion library mentioned earlier. 

While in the `notes/test` directory, type the following to install Mocha and Chai:

```

当然，这会设置一个`package.json`文件并安装所需的软件包。

除了 Mocha 和 Chai 之外，我们还安装了两个额外的工具。第一个是`cross-env`，这是我们以前使用过的，它可以在命令行上设置环境变量的跨平台支持。第二个是`npm-run-all`，它简化了使用`package.json`来驱动构建或测试过程。

有关`cross-env`的文档，请访问[`www.npmjs.com/package/cross-env`](https://www.npmjs.com/package/cross-env)。

有关`npm-run-all`的文档，请访问[`www.npmjs.com/package/npm-run-all`](https://www.npmjs.com/package/npm-run-all)。

有了设置好的工具，我们可以继续创建测试。

## Notes 模型测试套件

因为我们有几个 Notes 模型，测试套件应该针对任何模型运行。我们可以使用 NotesStore API 编写测试，并且应该使用环境变量来声明要测试的模型。因此，测试脚本将加载`notes-store.mjs`并调用它提供的对象上的函数。其他环境变量将用于其他配置设置。

因为我们使用 ES6 模块编写了 Notes 应用程序，所以我们需要考虑一个小问题。旧版的 Mocha 只支持在 CommonJS 模块中运行测试，因此这需要我们跳过一些步骤来测试 Notes 模块。但是当前版本的 Mocha 支持它们，这意味着我们可以自由使用 ES6 模块。

我们将首先编写一个单独的测试用例，并按照运行该测试和获取结果的步骤进行。之后，我们将编写更多的测试用例，甚至找到一些错误。这些错误将给我们一个机会来调试应用程序并解决任何问题。我们将通过讨论如何运行需要设置后台服务的测试来结束本节。

### 创建初始 Notes 模型测试用例

在`test`目录中，创建一个名为`test-model.mjs`的文件，其中包含以下内容。这将是测试套件的外壳：

```

This loads in the required modules and implements the first test case.

The Chai library supports three flavors of assertions. We're using the `assert` style here, but it's easy to use a different style if you prefer.

For the other assertion styles supported by Chai, see [`chaijs.com/guide/styles/`](http://chaijs.com/guide/styles/).

Chai's assertions include a very long list of useful assertion functions. For the documentation, see [`chaijs.com/api/assert/`](http://chaijs.com/api/assert/).

To load the model to be tested, we call the `useModel` function (renamed as `useNotesModel`). You'll remember that this uses the `import()` function to dynamically select the actual NotesStore implementation to use. The `NOTES_MODEL` environment variable is used to select which to load.

Calling `this.timeout` adjusts the time allowed for completing the test. By default, Mocha allows 2,000 milliseconds (2 seconds) for a test case to be completed. This particular test case might take longer than that, so we've given it more time.

The test function is declared as `async`.  Mocha can be used in a callback fashion, where Mocha passes in a callback to the test to invoke and indicate errors. However, it can also be used with `async` test functions, meaning that we can throw errors in the normal way and Mocha will automatically capture those errors to determine if the test fails.

Generally, Mocha looks to see if the function throws an exception or whether the test case takes too long to execute (a timeout situation). In either case, Mocha will indicate a test failure. That's, of course, simple to determine for non-asynchronous code. But Node.js is all about asynchronous code, and Mocha has two models for testing asynchronous code. In the first (not seen here), Mocha passes in a callback function, and the test code is to call the callback function. In the second, as seen here, it looks for a Promise being returned by the test function and determines a pass/fail regarding whether the Promise is in the `resolve` or `reject` state.

We are keeping the NotesStore model in the global `store` variable so that it can be used by all tests. The test, in this case, is whether we can load a given NotesStore implementation. As the comment states, if this executes without throwing an exception, the test has succeeded.  The other purpose of this test is to initialize the variable for use by other test cases.

It is useful to notice that this code carefully avoids loading `app.mjs`. Instead, it loads the test driver module, `models/notes-store.mjs`, and whatever module is loaded by `useNotesModel`. The `NotesStore` implementation is what's being tested, and the spirit of unit testing says to isolate it as much as possible.

Before we proceed further, let's talk about how Mocha structures tests.

With Mocha, a test suite is contained within a `describe` block. The first argument is a piece of descriptive text that you use to tailor the presentation of test results. The second argument is a `function` that contains the contents of the given test suite.

The `it` function is a test case. The intent is for us to read this as *it should successfully load the module*. Then, the code within the `function` is used to check that assertion.

With Mocha, it is important to not use arrow functions in the `describe` and `it` blocks. By now, you will have grown fond of arrow functions because of how much easier they are to write. However, Mocha calls these functions with a `this` object containing useful functions for Mocha. Because arrow functions avoid setting up a `this` object, Mocha would break.

Now that we have a test case written, let's learn how to run tests.

### Running the first test case

Now that we have a test case, let's run the test. In the `package.json` file, add the following `scripts` section:

```

我们在这里做的是创建一个`test-all`脚本，它将针对各个 NotesStore 实现运行测试套件。我们可以运行此脚本来运行每个测试组合，或者我们可以运行特定脚本来测试只有一个组合。例如，`test-notes-sequelize-sqlite`将针对使用 SQLite3 数据库的`SequelizeNotesStore`运行测试。

它使用`npm-run-all`来支持按顺序运行测试。通常，在`package.json`脚本中，我们会这样写：

```

This runs a series of steps one after another, relying on a feature of the Bash shell. The `npm-run-all` tool serves the same purpose, namely running one `package.json` script after another in the series. The first advantage is that the code is simpler and more compact, making it easier to read, while the other advantage is that it is cross-platform. We're using `cross-env` for the same purpose so that the test scripts can be executed on Windows as easily as they can be on Linux or macOS.

For the `test-notes-sequelize-sqlite` test, look closely. Here, you can see that we need a database configuration file named `sequelize-sqlite.yaml`. Create that file with the following code:

```

正如测试脚本名称所示，这使用 SQLite3 作为底层数据库，并将其存储在指定的文件中。

我们缺少两种组合，`test-notes-sequelize-mysql`用于使用 MySQL 的`SequelizeNotesStore`和`test-notes-mongodb`，它测试`MongoDBNotesStore`。我们稍后将实现这些组合。

自动运行所有测试组合后，我们可以尝试一下：

```

If all has gone well, you'll get this result for every test combination currently supported in the `test-all` script.

This completes the first test, which was to demonstrate how to create tests and execute them. All that remains is to write more tests.

### Adding some tests

That was easy, but if we want to find what bugs we created, we need to test some functionality. Now, let's create a test suite for testing `NotesStore`, which will contain several test suites for different aspects of `NotesStore`.

What does that mean? Remember that the `describe` function is the container for a test suite and that the `it` function is the container for a test case. By simply nesting `describe` functions, we can contain a test suite within a test suite. It will be clearer what that means after we implement this:

```

在这里，我们有一个`describe`函数，它定义了一个包含另一个`describe`函数的测试套件。这是嵌套测试套件的结构。

目前在`it`函数中没有测试用例，但是我们有`before`和`after`函数。这两个函数的功能就像它们的名字一样；`before`函数在所有测试用例之前运行，而`after`函数在所有测试用例完成后运行。`before`函数旨在设置将被测试的条件，而`after`函数旨在进行拆卸。

在这种情况下，`before`函数向`NotesStore`添加条目，而`after`函数删除所有条目。其想法是在每个嵌套测试套件执行后都有一个干净的状态。

`before`和`after`函数是 Mocha 称之为钩子的函数。其他钩子是`beforeEach`和`afterEach`。区别在于`Each`钩子在每个测试用例执行之前或之后触发。

这两个钩子也充当测试用例，因为`create`和`destroy`方法可能会失败，如果失败，钩子也会失败。

在`before`和`after`钩子函数之间，添加以下测试用例：

```

As suggested by the description for this test suite, the functions all test the `keylist` method.

For each test case, we start by calling `keylist`, then using `assert` methods to check different aspects of the array that is returned. The idea is to call `NotesStore` API functions, then test the results to check whether they matched the expected results.

Now, we can run the tests and get the following:

```

将输出与`describe`和`it`函数中的描述字符串进行比较。您会发现，此输出的结构与测试套件和测试用例的结构相匹配。换句话说，我们应该将它们结构化，使其具有良好结构化的测试输出。

正如他们所说，测试永远不会完成，只会耗尽。所以，在我们耗尽之前，让我们看看我们能走多远。

### Notes 模型的更多测试

这还不足以进行太多测试，所以让我们继续添加一些测试：

```

These tests check the `read` method. In the first test case, we check whether it successfully reads a known Note, while in the second test case, we have a negative test of what happens if we read a non-existent Note.

Negative tests are very important to ensure that functions fail when they're supposed to fail and that failures are indicated correctly.

The Chai Assertions API includes some very expressive assertions. In this case, we've used the `deepEqual` method, which does a deep comparison of two objects. You'll see that for the first argument, we pass in an object and that for the second, we pass an object that's used to check the first. To see why this is useful, let's force it to indicate an error by inserting `FAIL` into one of the test strings.

After running the tests, we get the following output:

```

这就是失败的测试样子。没有勾号，而是一个数字，数字对应下面的报告。在失败报告中，`deepEqual`函数为我们提供了关于对象字段差异的清晰信息。在这种情况下，这是我们故意让`deepEqual`函数失败的测试，因为我们想看看它是如何工作的。

请注意，对于负面测试——如果抛出错误则测试通过——我们在`try/catch`块中运行它。每种情况中的`throw new Error`行不应该执行，因为前面的代码应该抛出一个错误。因此，我们可以检查抛出的错误中的消息是否是到达的消息，并且如果是这种情况，则使测试失败。

### 诊断测试失败

我们可以添加更多的测试，因为显然，这些测试还不足以能够将 Notes 发布给公众。这样做之后，运行测试以针对不同的测试组合，我们将在 SQLite3 组合的结果中找到这个结果：

```

Our test suite found two errors, one of which is the error we mentioned in Chapter 7, *Data Storage and Retrieval*. Both failures came from the negative test cases. In one case, the test calls `store.read("badkey12")`, while in the other, it calls `store.delete("badkey12")`.

It is easy enough to insert `console.log` calls and learn what is going on.

For the `read` method, SQLite3 gave us `undefined` for `row`. The test suite successfully calls the `read` function multiple times with a `notekey` value that does exist. Obviously, the failure is limited to the case of an invalid `notekey` value. In such cases, the query gives an empty result set and SQLite3 invokes the callback with `undefined` in both the error and the row values. Indeed, the equivalent `SQL SELECT` statement does not throw an error; it simply returns an empty result set. An empty result set isn't an error, so we received no error and an undefined `row`.

However, we defined `read` to throw an error if no such Note exists. This means this function must be written to detect this condition and throw an error.

There is a difference between the `read` functions in `models/notes-sqlite3.mjs` and `models/notes-sequelize.mjs`. On the day we wrote `SequelizeNotesStore`, we must have thought through this function more carefully than we did on the day we wrote `SQLITE3NotesStore`. In `SequelizeNotesStore.read`, there is an error that's thrown when we receive an empty result set, and it has a check that we can adapt. Let's rewrite the `read` function in `models/notes-sqlite.mjs` so that it reads as follows:

```

如果这收到一个空结果，就会抛出一个错误。虽然数据库不会将空结果集视为错误，但 Notes 会。此外，Notes 已经知道如何处理这种情况下抛出的错误。进行这个更改，那个特定的测试用例就会通过。

`destroy`逻辑中还有第二个类似的错误。在 SQL 中，如果这个 SQL（来自`models/notes-sqlite3.mjs`）没有删除任何内容，这显然不是一个 SQL 错误：

```

Unfortunately, there isn't a method in the SQL option to fail if it does not delete any records. Therefore, we must add a check to see if a record exists, namely the following:

```

因此，我们读取笔记，并且作为副产品，我们验证笔记是否存在。如果笔记不存在，`read`将抛出一个错误，而`DELETE`操作甚至不会运行。

当我们运行`test-notes-sequelize-sqlite`时，它的`destroy`方法也出现了类似的失败。在`models/notes-sequelize.mjs`中，进行以下更改：

```

This is the same change; that is, to first `read` the Note corresponding to the given `key`, and if the Note does not exist, to throw an error.

Likewise, when running `test-level`, we get a similar failure, and the solution is to edit `models/notes-level.mjs` to make the following change:

```

与其他 NotesStore 实现一样，在销毁之前先读取 Note。如果`read`操作失败，那么测试用例会看到预期的错误。

这些是我们在第七章中提到的错误，*数据存储和检索*。我们只是忘记在这个特定模型中检查这些条件。幸运的是，我们勤奋的测试捕捉到了问题。至少，这是要告诉经理的故事，而不是告诉他们我们忘记检查我们已经知道可能发生的事情。

### 针对需要服务器设置的数据库进行测试——MySQL 和 MongoDB

这很好，但显然我们不会在生产中使用 SQLite3 或 Level 等数据库运行 Notes。我们可以在 Sequelize 支持的 SQL 数据库（如 MySQL）和 MongoDB 上运行 Notes。显然，我们疏忽了没有测试这两种组合。

我们的测试结果矩阵如下：

+   `notes-fs`: 通过

+   `notes-memory`: 通过

+   `notes-level`: 1 个失败，现已修复

+   `notes-sqlite3`: 2 个失败，现已修复

+   `notes-sequelize`: 使用 SQLite3：1 个失败，现已修复

+   `notes-sequelize`: 使用 MySQL：未经测试

+   `notes-mongodb`: 未经测试

两个未经测试的 NotesStore 实现都需要我们设置一个数据库服务器。我们避免测试这些组合，但我们的经理不会接受这个借口，因为 CEO 需要知道我们已经完成了测试周期。笔记必须使用类似于生产环境的配置进行测试。

在生产中，我们将使用常规的数据库服务器，MySQL 或 MongoDB 是主要选择。因此，我们需要一种低开销的方式来对这些数据库进行测试。对生产配置进行测试必须如此简单，以至于我们在进行测试时不会感到阻力，以确保测试运行得足够频繁，以产生期望的影响。

在本节中，我们取得了很大的进展，并在 NotesStore 数据库模块的测试套件上有了一个良好的开端。我们学会了如何在 Mocha 中设置测试套件和测试用例，以及如何获得有用的测试报告。我们学会了如何使用`package.json`来驱动测试套件执行。我们还学会了负面测试场景以及如何诊断出现的错误。

但我们需要解决针对数据库服务器进行测试的问题。幸运的是，我们已经使用了一个支持轻松创建和销毁部署基础设施的技术。你好，Docker！

在下一节中，我们将学习如何将 Docker Compose 部署重新用作测试基础设施。

# 使用 Docker Swarm 管理测试基础设施

Docker 给我们带来的一个优势是能够在我们的笔记本电脑上安装生产环境。在第十二章中，*使用 Terraform 将 Docker Swarm 部署到 AWS EC2*，我们将一个在我们的笔记本电脑上运行的 Docker 设置转换为可以部署在真实云托管基础设施上的设置。这依赖于将 Docker Compose 文件转换为 Docker Stack 文件，并对我们在 AWS EC2 实例上构建的环境进行定制。

在本节中，我们将将 Stack 文件重新用作部署到 Docker Swarm 的测试基础设施。一种方法是简单地运行相同的部署，到 AWS EC2，并替换`var.project_name`和`var.vpc_name`变量的新值。换句话说，EC2 基础设施可以这样部署：

```

This would deploy a second VPC with a different name that's explicitly for test execution and that would not disturb the production deployment. It's quite common in Terraform to customize the deployment this way for different targets.

In this section, we'll try something different. We can use Docker Swarm in other contexts, not just the AWS EC2 infrastructure we set up. Specifically, it is easy to use Docker Swarm with the Docker for Windows or Docker for macOS that's running on our laptop.

What we'll do is configure Docker on our laptop so that it supports swarm mode and create a slightly modified version of the Stack file in order to run the tests on our laptop. This will solve the issue of running tests against a MySQL database server, and also lets us test the long-neglected MongoDB module. This will demonstrate how to use Docker Swarm for test infrastructure and how to perform semi-automated test execution inside the containers using a shell script.

Let's get started.

## Using Docker Swarm to deploy test infrastructure

We had a great experience using Docker Compose and Swarm to orchestrate Notes application deployment on both our laptop and our AWS infrastructure. The whole system, with five independent services, is easily described in `compose-local/docker-compose.yml` and `compose-swarm/docker-compose.yml`. What we'll do is duplicate the Stack file, then make a couple of small changes required to support test execution in a local swarm.

To configure the Docker installation on our laptop for swarm mode, simply type the following:

```

与以前一样，这将打印有关加入令牌的消息。如果需要的话，如果你的办公室有多台电脑，你可能会对设置本地 Swarm 进行实验感兴趣。但对于这个练习来说，这并不重要。这是因为我们可以用单节点 Swarm 完成所有需要的工作。

这不是单行道，这意味着当你完成这个练习时，关闭 swarm 模式是很容易的。只需关闭部署到本地 Swarm 的任何内容，并运行以下命令：

```

Normally, this is used for a host that you wish to detach from an existing swarm. If there is only one host remaining in a swarm, the effect will be to shut down the swarm.

Now that we know how to initialize swarm mode on our laptop, let's set about creating a stack file suitable for use on our laptop.

Create a new directory, `compose-stack-test-local`, as a sibling to the `notes`, `users`, and `compose-local` directories. Copy `compose-stack/docker-compose.yml` to that directory. We'll be making several small changes to this file and no changes to the existing Dockerfiles. As much as it is possible, it is important to test the same containers that are used in the production deployment. This means it's acceptable to inject test files into the containers, but not modify them.

Make every `deploy` tag look like this:

```

这将删除我们在 AWS EC2 上声明的放置约束，并将其设置为每个服务的一个副本。对于单节点集群，当然我们不用担心放置，也没有必要多个服务实例。

对于数据库服务，删除`volumes`标签。当需要在数据库数据目录中持久保存数据时，使用此标签是必需的。对于测试基础设施，数据目录并不重要，可以随意丢弃。同样，删除顶级`volumes`标签。

对于`svc-notes`和`svc-userauth`服务，进行以下更改：

```

This injects the files required for testing into the `svc-notes` container. Obviously, this is the `test` directory that we created in the previous section for the Notes service. Those tests also require the SQLite3 schema file since it is used by the corresponding test script. In both cases, we can use `bind` mounts to inject the files into the running container.

The Notes test suite follows a normal practice for Node.js projects of putting `test` files in the test directory. When building the container, we obviously don't include the test files because they're not required for deployment. But running tests requires having that directory inside the running container. Fortunately, Docker makes this easy. We simply mount the directory into the correct place.

The bottom line is this approach gives us the following advantages:

*   The test code is in `notes/test`, where it belongs.
*   The test code is not copied into the production container.
*   In test mode, the `test` directory appears where it belongs.

For Docker (using `docker run`) and Docker Compose, the volume is mounted from a directory on the localhost. But for swarm mode, with a multi-node swarm, the container could be deployed on any host matching the placement constraints we declare. In a swarm, bind volume mounts like the ones shown here will try to mount from a directory on the host that the container has been deployed in. But we are not using a multi-node swarm; instead, we are using a single-node swarm. Therefore, the container will mount the named directory from our laptop, and all will be fine. But as soon as we decide to run testing on a multi-node swarm, we'll need to come up with a different strategy for injecting these files into the container.

We've also changed the `ports` mappings. For `svc-userauth`, we've made its port visible to give ourselves the option of testing the REST service from the host computer. For the `svc-notes` service, this will make it appear on port `3000`. In the `environment` section, make sure you did not set a `PORT` variable. Finally, we adjust `TWITTER_CALLBACK_HOST` so that it uses `localhost:3000` since we're deploying on the localhost.

For both services, we're changing the image tag from the one associated with the AWS ECR repository to one of our own designs. We won't be publishing these images to an image repository, so we can use any image tag we like.  

For both services, we are using the Sequelize data model, using the existing MySQL-oriented configuration file, and setting the `SEQUELIZE_DBHOST` variable to refer to the container holding the database. 

We've defined a Docker Stack file that should be useful for deploying the Notes application stack in a Swarm. The difference between the deployment on AWS EC2 and here is simply the configuration. With a few simple configuration changes, we've mounted test files into the appropriate container, reconfigured the volumes and the environment variables, and changed the deployment descriptors so that they're suitable for a single-node swarm running on our laptop.

Let's deploy this and see how well we did.

## Executing tests under Docker Swarm

We've repurposed our Docker Stack file so that it describes deploying to a single-node swarm, ensuring the containers are set up to be useful for testing. Our next step is to deploy the Stack to a swarm and execute the tests inside the Notes container.

To set it up, run the following commands:

```

我们运行`swarm init`在我们的笔记本上打开 swarm 模式，然后将两个`TWITTER`秘密添加到 swarm 中。由于它是单节点 swarm，我们不需要运行`docker swarm join`命令来添加新节点到 swarm 中。

然后，在`compose-stack-test-local`目录中，我们可以运行这些命令：

```

Because a Stack file is also a Compose file, we can run `docker-compose build` to build the images. Because of the `image` tags, this will automatically tag the images so that they match the image names we specified.

Then, we use `docker stack deploy`, as we did when deploying to AWS EC2\. Unlike the AWS deployment, we do not need to push the images to repositories, which means we do not need to use the `--with-registry-auth` option. This will behave almost identically to the swarm we deployed to EC2, so we explore the deployed services in the same way:

```

因为这是单主机 swarm，我们不需要使用 SSH 访问 swarm 节点，也不需要使用`docker context`设置远程访问。相反，我们运行 Docker 命令，它们会在本地主机上的 Docker 实例上执行。 

`docker ps`命令将告诉我们每个服务的精确容器名称。有了这个知识，我们可以运行以下命令来获得访问权限：

```

Because, in swarm mode, the containers have unique names, we have to run `docker ps` to get the container name, then paste it into this command to start a Bash shell inside the container.

Inside the container, we see the `test` directory is there as expected. But we have a couple of setup steps to perform. The first is to install the SQLite3 command-line tools since the scripts in `package.json` use that command. The second is to remove any existing `node_modules` directory because we don't know if it was built for this container or for the laptop. After that, we need to run `npm install` to install the dependencies.

Having done this, we can run the tests:

```

测试应该像在我们的笔记本电脑上一样执行，但是它们是在容器内运行的。但是，MySQL 测试不会运行，因为`package.json`脚本没有设置自动运行。因此，我们可以将其添加到`package.json`中：

```

This is the command that's required to execute the test suite against the MySQL database.

Then, we can run the tests against MySQL, like so:

```

测试应该对 MySQL 执行正确。

为了自动化这一过程，我们可以创建一个名为`run.sh`的文件，其中包含以下代码：

```

The script executes each script in `notes/test/package.json` individually. If you prefer, you can replace these with a single line that executes `npm run test-all`.

This script takes a command-line argument for the container name holding the `svc-notes` service. Since the tests are located in that container, that's where the tests must be run. The script can be executed like so:

```

这运行了前面的脚本，将每个测试组合单独运行，并确保`DEBUG`变量未设置。这个变量在 Dockerfile 中设置，会导致在测试结果输出中打印调试信息。在脚本中，`--workdir`选项将命令的当前目录设置为`test`目录，以简化运行测试脚本。

当然，这个脚本在 Windows 上不会直接执行。要将其转换为 PowerShell 使用，将从第二行开始的文本保存到`run.ps1`中，然后将`SVC_NOTES`引用更改为`%SVC_NOTES%`引用。

我们已经成功地将大部分测试矩阵的执行部分自动化。但是，测试矩阵中存在一个明显的漏洞，即缺乏对 MongoDB 的测试。填补这个漏洞将让我们看到如何在 Docker 下设置 MongoDB。

### 在 Docker 下设置 MongoDB 并对 Notes 进行测试

在第七章，*数据存储和检索*中，我们为 Notes 开发了 MongoDB 支持。从那时起，我们专注于`Sequelize`。为了弥补这一点，让我们确保至少测试我们的 MongoDB 支持。在 MongoDB 上进行测试只需要定义一个 MongoDB 数据库的容器和一点配置。

访问[`hub.docker.com/_/mongo/`](https://hub.docker.com/_/mongo/)获取官方 MongoDB 容器。您可以将其改装以部署在 MongoDB 上运行的 Notes 应用程序。

将以下代码添加到`compose-stack-test-local/docker-compose.yml`中：

```

That's all that's required to add a MongoDB container to a Docker Compose/Stack file. We've connected it to `frontnet` so that the database is accessible by `svc-notes`. If we wanted the `svc-notes` container to use MongoDB, we'd need some environment variables (`MONGO_URL`, `MONGO_DBNAME`, and `NOTES_MODEL`) to tell Notes to use MongoDB. 

But we'd also run into a problem that we created for ourselves in Chapter 9, *Dynamic Client/Server Interaction with Socket.IO*. In that chapter, we created a messaging subsystem so that our users can leave messages for each other. That messaging system is currently implemented to store messages in the same Sequelize database where the Notes are stored. But to run Notes with no Sequelize database would mean a failure in the messaging system. Obviously, the messaging system can be rewritten, for instance, to allow storage in a MongoDB database, or to support running both MongoDB and Sequelize at the same time.

Because we were careful, we can execute code in `models/notes-mongodb.mjs` without it being affected by other code. With that in mind, we'll simply execute the Notes test suite against MongoDB and report the results.

Then, in `notes/test/package.json`, we can add a line to facilitate running tests on MongoDB:

```

我们只是将 MongoDB 容器添加到了`frontnet`，使得数据库可以在此处显示的 URL 上使用。因此，现在可以简单地使用 Notes MongoDB 模型运行测试套件。

`--no-timeouts`选项是必要的，以避免针对 MongoDB 测试套件时出现错误。此选项指示 Mocha 不检查测试用例执行是否太长时间。

最后的要求是将以下一行添加到`run.sh`（或`run.ps1`适用于 Windows）中：

```

This ensures MongoDB can be tested alongside the other test combinations. But when we run this, an error might crop up:

```

问题在于 MongoClient 对象的初始化程序略有变化。因此，我们必须修改`notes/models/notes-mongodb.mjs`，使用这个新的`connectDB`函数：

```

This adds a pair of useful configuration options, including the option explicitly named in the error message. Otherwise, the code is unchanged.

To make sure the container is running with the updated code, rerun the `docker-compose build` and `docker stack deploy` steps shown earlier. Doing so rebuilds the images, and then updates the services. Because the `svc-notes` container will relaunch, you'll need to install the Ubuntu `sqlite3` package again.

Once you've done that, the tests will all execute correctly, including the MongoDB combination.

We can now report the final test results matrix to the manager:

*   `models-fs`: PASS
*   `models-memory`: PASS
*   `models-levelup`: 1 failure, now fixed, PASS
*   `models-sqlite3`: Two failures, now fixed, PASS
*   `models-sequelize` with SQLite3: 1 failure, now fixed, PASS
*   `models-sequelize` with MySQL: PASS
*   `models-mongodb`: PASS

The manager will tell you "good job" and then remember that the models are only a portion of the Notes application. We've left two areas completely untested:

*   The REST API for the user authentication service
*   Functional testing of the user interface

In this section, we've learned how to repurpose a Docker Stack file so that we can launch the Notes stack on our laptop. It took a few simple reconfigurations of the Stack file and we were ready to go, and we even injected the files that are useful for testing. With a little bit more work, we finished testing against all configuration combinations of the Notes database modules.

Our next task is to handle testing the REST API for the user authentication service.

# Testing REST backend services

It's now time to turn our attention to the user authentication service. We've mentioned testing this service, saying that we'll get to them later. We developed a command-line tool for both administration and ad hoc testing. While that has been useful all along, it's time to get cracking with some real tests.

There's a question of which tool to use for testing the authentication service. Mocha does a good job of organizing a series of test cases, and we should reuse it here. But the thing we have to test is a REST service. The customer of this service, the Notes application, uses it through the REST API, giving us a perfect rationalization to test the REST interface rather than calling the functions directly. Our ad hoc scripts used the SuperAgent library to simplify making REST API calls. There happens to be a companion library, SuperTest, that is meant for REST API testing. It's easy to use that library within a Mocha test suite, so let's take that route.

For the documentation on SuperTest, look here: [`www.npmjs.com/package/supertest`](https://www.npmjs.com/package/supertest).

Create a directory named `compose-stack-test-local/userauth`. This directory will contain a test suite for the user authentication REST service. In that directory, create a file named `test.mjs` that contains the following code:

```

这设置了 Mocha 和 SuperTest 客户端。`URL_USERS_TEST`环境变量指定了要针对其运行测试的服务器的基本 URL。鉴于我们之前使用的配置，您几乎肯定会使用`http://localhost:5858`，但它可以是指向任何主机的任何 URL。SuperTest 的初始化方式与 SuperAgent 略有不同。

`SuperTest`模块提供了一个函数，我们使用`URL_USERS_TEST`变量调用该函数。这给了我们一个对象，我们称之为`request`，用于与正在测试的服务进行交互。

我们还设置了一对变量来存储认证用户 ID 和密钥。这些值与用户认证服务器中的值相同。我们只需要在进行 API 调用时提供它们。

最后，这是 Mocha 测试套件的外壳。所以，让我们开始填写`before`和`after`测试用例：

```

These are our `before` and `after` tests. We'll use them to establish a user and then clean them up by removing the user at the end.

This gives us a taste of how the `SuperTest` API works. If you refer back to `cli.mjs`, you'll see the similarities to `SuperAgent`.

The `post` and `delete` methods we can see here declare the HTTP verb to use. The `send` method provides an object for the `POST` operation. The `set` method sets header values, while the `auth` method sets up authentication:

```

现在，我们可以测试一些 API 方法，比如`/list`操作。

我们已经保证在`before`方法中有一个帐户，所以`/list`应该给我们一个包含一个条目的数组。

这遵循了使用 Mocha 测试 REST API 方法的一般模式。首先，我们使用 SuperTest 的`request`对象调用 API 方法并`await`其结果。一旦我们得到结果，我们使用`assert`方法来验证它是否符合预期。

添加以下测试用例：

```

We are checking the `/find` operation in two ways:

*   **Positive test**: Looking for the account we know exists – failure is indicated if the user account is not found
*   **Negative test**: Looking for the one we know does not exist – failure is indicated if we receive something other than an error or an empty object

Add the following test case:

```

最后，我们应该检查`/destroy`操作。这个操作已经在`after`方法中检查过，我们在那里`destroy`了一个已知的用户帐户。我们还需要执行负面测试，并验证其对我们知道不存在的帐户的行为。

期望的行为是抛出错误或结果显示一个指示错误的 HTTP `status`。实际上，当前的认证服务器代码给出了 500 状态码，以及其他一些信息。

这给了我们足够的测试来继续并自动化测试运行。

在`compose-stack-test-local/docker-compose.yml`中，我们需要将`test.js`脚本注入到`svc-userauth-test`容器中。我们将在这里添加：

```

This injects the `userauth` directory into the container as the `/userauth/test` directory. As we did previously, we then must get into the container and run the test script.

The next step is creating a `package.json` file to hold any dependencies and a script to run the test:

```

在依赖项中，我们列出了 Mocha，Chai，SuperTest 和 cross-env。然后，在`test`脚本中，我们运行 Mocha 以及所需的环境变量。这应该运行测试。

我们可以从我们的笔记本电脑使用这个测试套件。因为测试目录被注入到容器中，我们也可以在容器内运行它们。要这样做，将以下代码添加到`run.sh`中：

```

This adds a second argument – in this case, the container name for `svc-userauth`. We can then run the test suite, using this script to run them inside the container. The first two commands ensure the installed packages were installed for the operating system in this container, while the last runs the test suite.

Now, if you run the `run.sh` test script, you'll see the required packages get installed. Then, the test suite will be executed.

The result will look like this:

```

因为`URL_USERS_TEST`可以使用任何 URL，我们可以针对用户认证服务的任何实例运行测试套件。例如，我们可以使用适当的`URL_USERS_TEST`值从我们的笔记本电脑上测试在 AWS EC2 上部署的实例。

我们取得了很好的进展。我们现在已经为笔记和用户认证服务准备了测试套件。我们已经学会了如何使用 REST API 测试 REST 服务。这与直接调用内部函数不同，因为它是对完整系统的端到端测试，扮演服务的消费者角色。

我们的下一个任务是自动化测试结果报告。

# 自动化测试结果报告

我们已经自动化了测试执行，Mocha 通过所有这些勾号使测试结果看起来很好。但是，如果管理层想要一个显示测试失败趋势的图表怎么办？报告测试结果作为数据而不是作为控制台上的用户友好的打印输出可能有很多原因。

例如，测试通常不是在开发人员的笔记本电脑上运行，也不是由质量团队的测试人员运行，而是由自动化后台系统运行。CI/CD 模型被广泛使用，其中测试由 CI/CD 系统在每次提交到共享代码存储库时运行。当完全实施时，如果在特定提交上所有测试都通过，那么系统将自动部署到服务器，可能是生产服务器。在这种情况下，用户友好的测试结果报告是没有用的，而必须以数据的形式传递，可以在 CI/CD 结果仪表板网站上显示。

Mocha 使用所谓的**Reporter**来报告测试结果。Mocha Reporter 是一个模块，以其支持的任何格式打印数据。有关此信息的更多信息可以在 Mocha 网站上找到：[`mochajs.org/#reporters`](https://mochajs.org/#reporters)。

您将找到当前可用的`reporters`列表如下：

```

Then, you can use a specific Reporter, like so:

```

在`npm run script-name`命令中，我们可以注入命令行参数，就像我们在这里所做的那样。`--`标记告诉 npm 将其命令行的其余部分附加到执行的命令上。效果就像我们运行了这个命令：

```

For Mocha, the `--reporter` option selects which Reporter to use. In this case, we selected the TAP reporter, and the output follows that format.

**Test Anything Protocol** (**TAP**) is a widely used test results format that increases the possibility of finding higher-level reporting tools. Obviously, the next step would be to save the results into a file somewhere, after mounting a host directory into the container.

In this section, we learned about the test results reporting formats supported by Mocha. This will give you a starting point for collecting long-term results tracking and other useful software quality metrics. Often, software teams rely on quality metrics trends as part of deciding whether a product can be shipped to the public.

In the next section, we'll round off our tour of testing methodologies by learning about a framework for frontend testing.

# Frontend headless browser testing with Puppeteer

A big cost area in testing is manual user interface testing. Therefore, a wide range of tools has been developed to automate running tests at the HTTP level. Selenium is a popular tool implemented in Java, for example. In the Node.js world, we have a few interesting choices. The *chai-http* plugin to Chai would let us interact at the HTTP level with the Notes application while staying within the now-familiar Chai environment. 

However, in this section, we'll use Puppeteer ([`github.com/GoogleChrome/puppeteer`](https://github.com/GoogleChrome/puppeteer)). This tool is a high-level Node.js module used to control a headless Chrome or Chromium browser, using the DevTools protocol. This protocol allows tools to instrument, inspect, debug, and profile Chromium or Chrome browser instances. The key result is that we can test the Notes application in a real browser so that we have greater assurance it behaves correctly for users. 

The Puppeteer website has extensive documentation that's worth reading: [`pptr.dev/`](https://pptr.dev/).

Puppeteer is meant to be a general-purpose test automation tool and has a strong feature set for that purpose. Because it's easy to make web page screenshots with Puppeteer, it can also be used in a screenshot service.

Because Puppeteer is controlling a real web browser, your user interface tests will be very close to live browser testing, without having to hire a human to do the work. Because it uses a headless version of Chrome, no visible browser window will show on your screen, and tests can be run in the background instead. It can also drive other browsers by using the DevTools protocol.

First, let's set up a directory to work in.

## Setting up a Puppeteer-based testing project directory

First, let's set up the directory that we'll install Puppeteer in, as well as the other packages that will be required for this project:

```

这不仅安装了 Puppeteer，还安装了 Mocha、Chai 和 Supertest。我们还将使用`package.json`文件记录脚本。

在安装过程中，您会发现 Puppeteer 会导致 Chromium 被下载，就像这样：

```

The Puppeteer package will launch that Chromium instance as needed, managing it as a background process and communicating with it using the DevTools protocol.

The approach we'll follow is to test against the Notes stack we've deployed in the test Docker infrastructure. Therefore, we need to launch that infrastructure:

```

根据您的需求，可能还需要执行`docker-compose build`。无论如何，这都会启动测试基础架构，并让您看到运行中的系统。

我们可以使用浏览器访问`http://localhost:3000`等网址。因为这个系统不包含任何用户，我们的测试脚本将不得不添加一个测试用户，以便测试可以登录并添加笔记。

另一个重要的事项是测试将在一个匿名的 Chromium 实例中运行。即使我们在正常的桌面浏览器中使用 Chrome，这个 Chromium 实例也与我们正常的桌面设置没有任何连接。从可测试性的角度来看，这是一件好事，因为这意味着您的测试结果不会受到个人网络浏览器配置的影响。另一方面，这意味着无法进行 Twitter 登录测试，因为该 Chromium 实例没有 Twitter 登录会话。

记住这些，让我们编写一个初始的测试套件。我们将从一个简单的初始测试用例开始，以证明我们可以在 Mocha 中运行 Puppeteer。然后，我们将测试登录和注销功能，添加笔记的能力，以及一些负面测试场景。我们将在本节中讨论如何改进 HTML 应用程序的可测试性。让我们开始吧。

## 为 Notes 应用程序堆栈创建一个初始的 Puppeteer 测试

我们的第一个测试目标是建立一个测试套件的大纲。我们需要按顺序执行以下操作：

1.  向用户身份验证服务添加一个测试用户。

1.  启动浏览器。

1.  访问首页。

1.  验证首页是否正常显示。

1.  关闭浏览器。

1.  删除测试用户。

这将确保我们有能力与启动的基础架构进行交互，启动浏览器并查看 Notes 应用程序。我们将继续执行策略并在测试后进行清理，以确保后续测试运行的干净环境，并添加，然后删除，一个测试用户。

在`notesui`目录中，创建一个名为`uitest.mjs`的文件，其中包含以下代码：

```

This imports and configures the required modules. This includes setting up `bcrypt` support in the same way that is used in the authentication server. We've also copied in the authentication key for the user authentication backend service. As we did for the REST test suite, we will use the `SuperTest` library to add, verify, and remove the test user using the REST API snippets copied from the REST tests.

Add the following test block:

```

这将向身份验证服务添加一个用户。回顾一下，您会发现这与 REST 测试套件中的测试用例类似。如果您需要验证阶段，还有另一个测试用例调用`/find/testme`端点来验证结果。由于我们已经验证了身份验证系统，因此我们不需要在这里重新验证它。我们只需要确保我们有一个已知的测试用户，可以在需要浏览器登录的场景中使用。

将此代码放在`uitest.mjs`的最后：

```

At the end of the test execution, we should run this to delete the test user. The policy is to clean up after we execute the test. Again, this was copied from the user authentication service test suite. Between those two, add the following:

```

记住，在`describe`中，测试是`it`块。`before`块在所有`it`块之前执行，`after`块在之后执行。

在`before`函数中，我们通过启动 Puppeteer 实例并启动一个新的 Page 对象来设置 Puppeteer。因为`puppeteer.launch`的`headless`选项设置为`false`，我们将在屏幕上看到一个浏览器窗口。这将很有用，因为我们可以看到发生了什么。`sloMo`选项也通过减慢浏览器交互来帮助我们看到发生了什么。在`after`函数中，我们调用这些对象的`close`方法来关闭浏览器。`puppeteer.launch`方法接受一个`options`对象，其中有很多值得学习的属性。

`browser`对象代表正在运行测试的整个浏览器实例。相比之下，`page`对象代表的是实质上是浏览器中当前打开的标签页。大多数 Puppeteer 函数都是异步执行的。因此，我们可以使用`async`函数和`await`关键字。

`timeout`设置是必需的，因为有时浏览器实例启动需要很长时间。我们慷慨地设置了超时时间，以最小化偶发测试失败的风险。

对于`it`子句，我们进行了少量的浏览器交互。作为浏览器标签页的包装器，`page`对象具有与管理打开标签页相关的方法。例如，`goto`方法告诉浏览器标签页导航到给定的 URL。在这种情况下，URL 是笔记主页，作为环境变量传递。

`waitForSelector`方法是一组等待特定条件的方法之一。这些条件包括`waitForFileChooser`、`waitForFunction`、`waitForNavigation`、`waitForRequest`、`waitForResponse`和`waitForXPath`。这些方法以及`waitFor`方法都会导致 Puppeteer 异步等待浏览器中发生的某些条件。这些方法的目的是给浏览器时间来响应某些输入，比如点击按钮。在这种情况下，它会等到网页加载过程中在给定的 CSS 选择器下有一个可见的元素。该选择器指的是在页眉中的登录按钮。

换句话说，这个测试访问笔记主页，然后等待直到登录按钮出现。我们可以称之为一个简单的冒烟测试，快速执行并确定基本功能是否存在。

### 执行初始的 Puppeteer 测试

我们已经启动了使用`docker-compose`的测试基础设施。要运行测试脚本，请将以下内容添加到`package.json`文件的脚本部分：

```

The test infrastructure we deployed earlier exposes the user authentication service on port `5858` and the Notes application on port `3000`. If you want to test against a different deployment, adjust these URLs appropriately. Before running this, the Docker test infrastructure must be launched, which should have already happened.

Let's try running this initial test suite:

```

我们已经成功地创建了可以运行这些测试的结构。我们已经设置了 Puppeteer 和相关的包，并创建了一个有用的测试。主要的收获是有一个结构可以在其基础上构建更多的测试。

我们的下一步是添加更多的测试。

## 在笔记中测试登录/注销功能

在上一节中，我们创建了测试笔记用户界面的大纲。关于应用程序的测试并不多，但我们证明了可以使用 Puppeteer 测试笔记。

在本节中，我们将添加一个实际的测试。也就是说，我们将测试登录和注销功能。具体步骤如下：

1.  使用测试用户身份登录。

1.  验证浏览器是否已登录。

1.  注销。

1.  验证浏览器是否已注销。

在`uitest.js`中，插入以下测试代码：

```

This is our test implementation for logging in and out. We have to specify the `timeout` value because it is a new `describe` block.

The `click` method takes a CSS selector, meaning this first click event is sent to the Login button. A CSS selector, as the name implies, is similar to or identical to the selectors we'd write in a CSS file. With a CSS selector, we can target specific elements on the page.

To determine the selector to use, look at the HTML for the templates and learn how to describe the element you wish to target. It may be necessary to add ID attributes into the HTML to improve testability.

The Puppeteer documentation refers to the CSS Selectors documentation on the Mozilla Developer Network website: [`developer.mozilla.org/en-US/docs/Web/CSS/CSS_Selectors`](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Selectors).

Clicking on the Login button will, of course, cause the Login page to appear. To verify this, we wait until the page contains a form that posts to `/users/login`. That form is in `login.hbs`.

The `type` method acts as a user typing text. In this case, the selectors target the `Username` and `Password` fields of the login form. The `delay` option inserts a pause of 100 milliseconds after typing each character. It was noted in testing that sometimes, the text arrived with missing letters, indicating that Puppeteer can type faster than the browser can accept.

The `page.keyboard` object has various methods related to keyboard events. In this case, we're asking to generate the equivalent to pressing *Enter* on the keyboard. Since, at that point, the focus is in the Login form, that will cause the form to be submitted to the Notes application. Alternatively, there is a button on that form, and the test could instead click on the button.

The `waitForNavigation` method has a number of options for waiting on page refreshes to finish. The selected option causes a wait until the DOM content of the new page is loaded.

The `$` method searches the DOM for elements matching the selector, returning an array of matching elements. If no elements match, `null` is returned instead. Therefore, this is a way to test whether the application got logged in, by looking to see if the page has a Logout button.

To log out, we click on the Logout button. Then, to verify the application logged out, we wait for the page to refresh and show a Login button:

```

有了这些，我们的新测试都通过了。请注意，执行一些测试所需的时间相当长。在调试测试时观察到了更长的时间，这就是我们设置长超时时间的原因。

这很好，但当然，还有更多需要测试的，比如添加笔记的能力。

## 测试添加笔记的能力

我们有一个测试用例来验证登录/注销功能。这个应用程序的重点是添加笔记，所以我们需要测试这个功能。作为副作用，我们将学习如何使用 Puppeteer 验证页面内容。

为了测试这个功能，我们需要按照以下步骤进行：

1.  登录并验证我们已经登录。

1.  点击“添加笔记”按钮进入表单。

1.  输入笔记的信息。

1.  验证我们是否显示了笔记，并且内容是正确的。

1.  点击删除按钮并确认删除笔记。

1.  验证我们最终进入了主页。

1.  注销。

你可能会想“*再次登录不是重复的吗*？”之前的测试集中在登录/注销上。当然，浏览器可能已经处于登录状态了吧？如果浏览器仍然登录，这个测试就不需要再次登录。虽然这是真的，但这会导致登录/注销场景的测试不完整。每个场景在用户是否登录方面都应该是独立的。为了避免重复，让我们稍微重构一下测试。

在`最外层`的描述块中，添加以下两个函数：

```

This is the same code as the code for the body of the test cases shown previously, but we've moved the code to their own functions. With this change, any test case that wishes to log into the test user can use these functions.

Then, we need to change the login/logout tests to this:

```

我们所做的只是将此处的代码移动到它们自己的函数中。这意味着我们可以在其他测试中重用这些函数，从而避免重复的代码。

将以下代码添加到`uitest.mjs`中的笔记创建测试套件：

```

These are our test cases for adding and deleting Notes. We start with the `doLogin` and `checkLogin` functions to ensure the browser is logged in.

After clicking on the Add Note button and waiting for the browser to show the form in which we enter the Note details, we need to enter text into the form fields. The `page.type` method acts as a user typing on a keyboard and types the given text into the field identified by the selector.

The interesting part comes when we verify the note being shown. After clicking the **Submit** button, the browser is, of course, taken to the page to view the newly created Note. To do this, we use `page.$eval` to retrieve text from certain elements on the screen.

The `page.$eval` method scans the page for matching elements, and for each, it calls the supplied callback function. The callback function is given the element, and in our case, we call the `textContent` method to retrieve the textual form of the element. Then, we're able to use the `assert.include` function to test that the element contains the required text.

The `page.url()` method, as its name suggests, returns the URL currently being viewed. We can test whether that URL contains `/notes/view` to be certain the browser is viewing a note.

To delete the note, we start by verifying that the **Delete** button is on the screen. Of course, this button is there if the user is logged in. Once the button is verified, we click on it and wait for the `FORM` that confirms that we want to delete the Note. Once it shows up, we can click on the button, after which we are supposed to land on the home page.

Notice that to find the Delete button, we need to refer to `a#notedestroy`. As it stands, the template in question does not have that ID anywhere. Because the HTML for the Delete button was not set up so that we could easily create a CSS selector, we must edit `views/noteedit.hbs` to change the Delete button to this:

```

我们所做的就是添加了 ID 属性。这是改进可测试性的一个例子，我们稍后会讨论。

我们使用的一种技术是调用`page.$`来查询给定元素是否在页面上。这种方法检查页面，返回一个包含任何匹配元素的数组。我们只是测试返回值是否非空，因为如果没有匹配元素，`page.$`会返回`null`。这是一种简单的测试元素是否存在的方法。

点击**注销**按钮退出登录。

创建了这些测试用例后，我们可以再次运行测试套件：

```

We have more passing tests and have made good progress. Notice how one of the test cases took 18 seconds to finish. That's partly because we slowed text entry down to make sure it is correctly received in the browser, and there is a fair amount of text to enter. There was a reason we increased the timeout.

In earlier tests, we had success with negative tests, so let's see if we can find any bugs that way.

## Implementing negative tests with Puppeteer

Remember that a negative test is used to purposely invoke scenarios that will fail. The idea is to ensure the application fails correctly, in the expected manner.

We have two scenarios for an easy negative test:

*   Attempt to log in using a bad user ID and password
*   Access a bad URL

Both of these are easy to implement, so let's see how it works.

### Testing login with a bad user ID

A simple way to ensure we have a bad username and password is to generate random text strings for both. An easy way to do that is with the `uuid` package. This package is about generating Universal Unique IDs (that is, UUIDs), and one of the modes of using the package simply generates a unique random string. That's all we need for this test; it is a guarantee that the string will be unique.

To make this crystal clear, by using a unique random string, we ensure that we don't accidentally use a username that might be in the database. Therefore, we will be certain of supplying an unknown username when trying to log in.

In `uitest.mjs`, add the following to the imports:

```

`uuid`包支持几种方法，`v4`方法是生成随机字符串的方法。

然后，添加以下场景：

```

This starts with the login scenario. Instead of a fixed username and password, we instead use the results of calling `uuidv4()`, or the random UUID string.

This does the login action, and then we wait for the resulting page. In trying this manually, we learn that it simply returns us to the login screen and that there is no additional message. Therefore, the test looks for the login form and ensures there is a Login button. Between the two, we are certain the user is not logged in.

We did not find a code error with this test, but there is a user experience error: namely, the fact that, for a failed login attempt, we simply show the login form and do not provide a message (that is, *unknown username or password*), which leads to a bad user experience. The user is left feeling confused over what just happened. So, let's put that on our backlog to fix.

### Testing a response to a bad URL 

Our next negative test is to try a bad URL in Notes. We coded Notes to return a 404 status code, which means the page or resource was not found. The test is to ask the browser to visit the bad URL, then verify that the result uses the correct error message.

Add the following test case:

```

通过获取主页的 URL（`NOTES_HOME_URL`）并将 URL 的*pathname*部分设置为`/bad-unknown-url`来计算错误的 URL。由于在笔记中没有这条路径，我们肯定会收到一个错误。如果我们想要更确定，似乎可以使用`uuidv4()`函数使 URL 变得随机。

调用`page.goto()`只是让浏览器转到请求的 URL。对于后续页面，我们等到出现一个带有`header`元素的页面。因为这个页面上没有太多内容，所以`header`元素是确定我们是否有了后续页面的最佳选择。

要检查 404 状态码，我们调用`response.status()`，这是在 HTTP 响应中收到的状态码。然后，我们调用`page.$eval`从页面中获取一些项目，并确保它们包含预期的文本。

在这种情况下，我们没有发现任何代码问题，但我们发现了另一个用户体验问题。错误页面非常丑陋且不友好。我们知道用户体验团队会对此大声抱怨，所以将其添加到待办事项中，以改进此页面。

在这一部分中，我们通过创建一些负面测试来结束了测试开发。虽然这并没有导致发现代码错误，但我们发现了一对用户体验问题。我们知道这将导致与用户体验团队进行不愉快的讨论，因此我们已经主动将修复这些页面的任务添加到了待办事项中。但我们也学会了随时留意沿途出现的任何问题。众所周知，由开发或测试团队发现的问题的修复成本最低。当用户社区报告问题时，修复问题的成本会大大增加。

在我们结束本章之前，我们需要更深入地讨论一下可测试性。

## 改进笔记 UI 的可测试性

虽然 Notes 应用程序在浏览器中显示良好，但我们如何编写测试软件来区分一个页面和另一个页面？正如我们在本节中看到的，UI 测试经常执行一个导致页面刷新的操作，并且必须等待下一个页面出现。这意味着我们的测试必须能够检查页面，并确定浏览器是否显示了正确的页面。一个错误的页面本身就是应用程序中的一个错误。一旦测试确定它是正确的页面，它就可以验证页面上的数据。

底线是，每个 HTML 元素必须能够轻松地使用 CSS 选择器进行定位。

虽然在大多数情况下，为每个元素编写 CSS 选择器很容易，在少数情况下，这很困难。**软件质量工程**（**SQE**）经理请求我们的帮助。涉及的是测试预算，SQE 团队能够自动化他们的测试，预算将被进一步拉伸。

所需的只是为 HTML 元素添加一些`id`或`class`属性，以提高可测试性。有了一些标识符和对这些标识符的承诺，SQE 团队可以编写可重复的测试脚本来验证应用程序。

我们已经看到了一个例子：`views/noteview.hbs`中的删除按钮。我们无法为该按钮编写 CSS 选择器，因此我们添加了一个 ID 属性，让我们能够编写测试。

总的来说，*可测试性*是为了软件质量测试人员的利益而向 API 或用户界面添加东西。对于 HTML 用户界面来说，这意味着确保测试脚本可以定位 HTML DOM 中的任何元素。正如我们所见，`id`和`class`属性在满足这一需求方面起到了很大作用。

在这一部分，我们学习了用户界面测试作为功能测试的一种形式。我们使用了 Puppeteer，一个用于驱动无头 Chromium 浏览器实例的框架，作为测试 Notes 用户界面的工具。我们学会了如何自动化用户界面操作，以及如何验证显示的网页是否与其正确的行为匹配。这包括覆盖登录、注销、添加笔记和使用错误的用户 ID 登录的测试场景。虽然这没有发现任何明显的失败，但观察用户交互告诉我们 Notes 存在一些可用性问题。

有了这些，我们准备结束本章。

# 总结

在本章中，我们涵盖了很多领域，并查看了三个不同的测试领域：单元测试、REST API 测试和 UI 功能测试。确保应用程序经过充分测试是通往软件成功的重要一步。一个不遵循良好测试实践的团队往往会陷入修复回归问题的泥潭。

首先，我们谈到了只使用断言模块进行测试的潜在简单性。虽然测试框架，比如 Mocha，提供了很好的功能，但我们可以用一个简单的脚本走得更远。

测试框架，比如 Mocha，有其存在的价值，至少是为了规范我们的测试用例并生成测试结果报告。我们用 Mocha 和 Chai 做到了这一点，这些工具非常成功。我们甚至在一个小的测试套件中发现了一些错误。

在开始单元测试之路时，一个设计考虑是模拟依赖关系。但并不总是一个好的做法用模拟版本替换每个依赖。因此，我们对一个实时数据库运行了我们的测试，但使用了测试数据。

为了减轻运行测试的行政负担，我们使用 Docker 来自动设置和拆除测试基础设施。就像 Docker 在自动部署 Notes 应用程序方面很有用一样，它在自动化测试基础设施部署方面也很有用。

最后，我们能够在真实的 Web 浏览器中测试 Notes 网络用户界面。我们不能指望单元测试能够找到每一个错误；有些错误只会在 Web 浏览器中显示。

在本书中，我们已经涵盖了 Node.js 开发的整个生命周期，从概念、通过各个开发阶段，到部署和测试。这将为您提供一个坚实的基础，从而开始开发 Node.js 应用程序。

在下一章中，我们将探讨另一个关键领域——安全性。我们将首先使用 HTTPS 对用户访问 Notes 进行加密和认证。我们将使用几个 Node.js 包来减少安全入侵的机会。


Node.js 应用程序中的安全性

我们即将结束学习 Node.js 的旅程。但还有一个重要的话题需要讨论：**安全**。您的应用程序的安全性非常重要。您想因为您的应用程序是自 Twitter 以来最伟大的东西而上新闻，还是因为通过您的网站发起的大规模网络安全事件而闻名？

多年来，全球各地的网络安全官员一直呼吁加强互联网安全。诸如互联网连接的安全摄像头之类的东西中的安全漏洞已被不法分子武器化为庞大的僵尸网络，并用于殴打网站或进行其他破坏。在其他情况下，由于安全入侵而导致的猖獗身份盗窃对我们所有人构成了财务威胁。几乎每天，新闻中都会有更多关于网络安全问题的揭示。

我们在本书中多次提到了这个问题。从第十章开始，即*在 Linux 上部署 Node.js 应用程序*，我们讨论了需要将 Notes 的部署分段以对抗入侵，并特别是将用户数据库隔离在受保护的容器中。您在关键系统周围放置的安全层越多，攻击者进入的可能性就越小。虽然 Notes 是一个玩具应用程序，但我们可以用它来学习如何实施 Web 应用程序安全。

安全不应该是事后才考虑的，就像测试不应该是事后才考虑的一样。两者都非常重要，即使只是为了避免公司因错误原因而上新闻。

在本章中，我们将涵盖以下主题：

+   在 AWS ECS 上为 Express 应用程序实施 HTTPS/SSL

+   使用 Helmet 库为内容安全策略、DNS 预取控制、帧选项、严格传输安全性和减轻 XSS 攻击实施标头

+   防止跨站点请求伪造攻击表单

+   SQL 注入攻击

+   对已知漏洞的软件包进行预部署扫描

+   审查 AWS 上可用的安全设施

对于一般建议，Express 团队在[`expressjs.com/en/advanced/best-practice-security.html`](https://expressjs.com/en/advanced/best-practice-security.html)上有一个出色的安全资源页面。

如果尚未这样做，请复制第十三章，*单元测试和功能测试*，源树，您可能已经称为`chap13`，以创建一个*安全*源树，您可以称为`chap14`。

在本章结束时，您将了解到提供 SSL 证书的详细信息，使用它们来实施 HTTPS 反向代理。之后，您将了解有关改进 Node.js Web 应用程序安全性的几种工具。这应该为您提供 Web 应用程序安全的基础。

让我们从为部署的 Notes 应用程序实施 HTTPS 支持开始。

# 第十八章：在部署的 Node.js 应用程序中为 Docker 实施 HTTPS

当前的最佳实践是每个网站都必须使用 HTTPS 访问。传输未加密信息的时代已经过去。这种旧模式容易受到中间人攻击和其他威胁的影响。

使用 SSL 和 HTTPS 意味着互联网连接经过身份验证和加密。加密足够好，可以阻止除最先进的窥探者之外的所有人，而身份验证意味着我们确信网站就是它所说的那样。HTTPS 使用 HTTP 协议，但使用 SSL 或安全套接字层进行加密。实施 HTTPS 需要获取 SSL 证书并在 Web 服务器或 Web 应用程序中实施 HTTPS 支持。

给定一个合适的 SSL 证书，Node.js 应用程序可以很容易地实现 HTTPS，因为只需少量代码就可以给我们一个 HTTPS 服务器。但还有另一种方法，可以提供额外的好处。NGINX 是一个备受推崇的 Web 服务器和代理服务器，非常成熟和功能丰富。我们可以使用它来实现 HTTPS 连接，并同时获得另一层保护，防止潜在的不法分子和 Notes 应用程序之间的攻击。

我们已经在 AWS EC2 集群上使用 Docker swarm 部署了 Notes。使用 NGINX 只是简单地向 swarm 添加另一个容器，配置所需的工具来提供 SSL 证书。为此，我们将使用一个将 NGINX 与 Let's Encrypt 客户端程序结合在一起，并编写脚本来自动更新证书的 Docker 容器。Let's Encrypt 是一个非营利性组织，提供免费 SSL 证书的优秀服务。使用他们的命令行工具，我们可以根据需要提供和管理 SSL 证书。

在这一部分，我们将做以下工作：

1.  配置一个域名指向我们的 swarm

1.  整合一个包含 NGINX、Cron 和 Certbot（Let's Encrypt 客户端工具之一）的 Docker 容器

1.  在该容器中实现自动化流程来管理证书的更新

1.  配置 NGINX 监听端口`443`（HTTPS）以及端口`80`（HTTP）

1.  配置 Twitter 应用程序以支持网站的 HTTPS

这可能看起来是很多工作，但每项任务都很简单。让我们开始吧。

## 为部署在 AWS EC2 上的应用程序分配一个域名

Notes 应用程序是使用在 AWS EC2 实例上构建的 Docker swarm 部署的。其中一个实例有一个由 AWS 分配的公共 IP 地址和域名。最好给 EC2 实例分配一个域名，因为 AWS 分配的名称不仅用户不友好，而且在下次重新部署集群时会更改。给 EC2 实例分配一个域名需要有一个注册的域名，添加一个列出其 IP 地址的 A 记录，并在 EC2 IP 地址更改时更新 A 记录。

添加 A 记录意味着什么？**域名系统**（**DNS**）是让我们可以使用`geekwisdom.net`这样的名称来访问网站，而不是 IP 地址`216.239.38.21`。在 DNS 协议中，有几种类型的*记录*可以与系统中的域名条目相关联。对于这个项目，我们只需要关注其中一种记录类型，即 A 记录，用于记录域名的 IP 地址。一个被告知访问任何域的网络浏览器会查找该域的 A 记录，并使用该 IP 地址发送网站内容的 HTTP(S)请求。

将 A 记录添加到域的 DNS 条目的具体方法在不同的域注册商之间差异很大。例如，一个注册商（Pair Domains）有这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/3537cb6a-f1b4-4f14-aaa7-58a7ad7c0d39.png)

在特定域的仪表板中，可能有一个用于添加新 DNS 记录的部分。在这个注册商中，下拉菜单可以让你在记录类型中进行选择。选择 A 记录类型，然后在你的域名中在右侧框中输入 IP 地址，在左侧框中输入子域名。在这种情况下，我们正在创建一个子域，`notes.geekwisdom.net`，这样我们就可以部署一个测试站点，而不会影响到托管在该域上的主站点。这也让我们避免了为这个项目注册一个新域名的费用。

一旦你点击“添加记录”按钮，A 记录就会被发布。由于 DNS 记录通常需要一些时间来传播，你可能无法立即访问域名。如果这需要超过几个小时，你可能做错了什么。

一旦 A 记录成功部署，你的用户就可以访问`notes.geekwisdom.net`这样一个漂亮的域名的 Notes 应用程序。

请注意，每次重新部署 EC2 实例时，IP 地址都会更改。如果重新部署 EC2 实例，则需要更新新地址的 A 记录。

在本节中，我们已经了解了将域名分配给 EC2 实例。这将使我们的用户更容易访问 Notes，同时也让我们可以提供 HTTPS/SSL 证书。

添加域名意味着更新 Twitter 应用程序配置，以便 Twitter 知道该域名。

## 更新 Twitter 应用程序

Twitter 需要知道哪些 URL 对我们的应用程序有效。到目前为止，我们已经告诉 Twitter 我们笔记本上的测试 URL。我们在一个真实域上有 Notes，我们需要告诉 Twitter 这一点。

我们已经做过这个几次了，所以你已经知道该怎么做了。前往`developers.twitter.com`，使用您的 Twitter 帐户登录，然后转到应用程序仪表板。编辑与您的 Notes 实例相关的应用程序，并将您的域名添加到 URL 列表中。

我们将为 Notes 应用程序实现 HTTP 和 HTTPS，因此 Notes 将具有`http://`和`https://` URL。这意味着您不仅必须将 HTTP URL 添加到 Twitter 配置站点，还必须将 HTTPS URL 添加到其中。

在`compose-stack/docker-compose.yml`文件中，`svc-notes`配置中的`TWITTER_CALLBACK_HOST`环境变量也必须使用该域名进行更新。

现在我们已经有了与 EC2 集群关联的域名，并且我们已经通知了 Twitter 该域名。我们应该能够重新部署 Notes 到集群，并能够使用该域名。这包括能够使用 Twitter 登录，创建和删除笔记等。在这一点上，您不能将 HTTPS URL 放入`TWITTER_CALLBACK_HOST`，因为我们还没有实现 HTTPS 支持。

这些步骤为在 Notes 上使用 Let's Encrypt 实现 HTTPS 做好了准备。但首先，让我们来了解一下 Let's Encrypt 的工作原理，以便更好地为 Notes 实现它。

## 规划如何使用 Let's Encrypt

与每个 HTTPS/SSL 证书提供商一样，Let's Encrypt 需要确保您拥有您正在请求证书的域。成功使用 Let's Encrypt 需要在发出任何 SSL 证书之前进行成功验证。一旦域名注册到 Let's Encrypt，注册必须至少每 90 天更新一次，因为这是他们 SSL 证书的到期时间。域名注册和证书更新因此是我们必须完成的两项主要任务。

在本节中，我们将讨论注册和更新功能的工作原理。我们的目标是了解我们将如何管理我们计划使用的任何域的 HTTPS 服务。

Let's Encrypt 支持 API，并且有几个客户端应用程序用于此 API。Certbot 是 Let's Encrypt 请求的推荐用户界面。它可以轻松安装在各种操作系统上。例如，它可以通过 Debian/Ubuntu 软件包管理系统获得。

有关 Let's Encrypt 文档，请参阅[`letsencrypt.org/docs/`](https://letsencrypt.org/docs/)。

有关 Certbot 文档，请参阅[`certbot.eff.org/docs/intro.html`](https://certbot.eff.org/docs/intro.html)。

验证域名所有权是 HTTPS 的核心特性，这使得它成为任何 SSL 证书供应商确保正确分发 SSL 证书的核心要求。Let's Encrypt 有几种验证策略，在这个项目中，我们将专注于其中一种，即 HTTP-01 挑战。

HTTP-01 挑战涉及 Let's Encrypt 服务向 URL 发出请求，例如`http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>`。`<TOKEN>`是 Let's Encrypt 提供的编码字符串，Certbot 工具将其写入目录中的文件。我们的任务是以某种方式允许 Let's Encrypt 服务器使用此 URL 检索该文件。

一旦 Certbot 成功地将域名注册到 Let's Encrypt，它将收到一对 PEM 文件，包括 SSL 证书。Certbot 跟踪各种管理细节和 SSL 证书，通常在`/etc/letsencrypt`目录中。然后必须使用 SSL 证书来实现 Notes 的 HTTPS 服务器。

Let's Encrypt SSL 证书在 90 天后过期，我们必须创建一个自动化的管理任务来更新证书。Certbot 也用于证书更新，通过运行`certbot renew`。这个命令查看在这台服务器上注册的域名，并对任何需要更新的域名重新运行验证过程。因此，必须保持启用 HTTP-01 挑战所需的目录。

拥有 SSL 证书后，我们必须配置一些 HTTP 服务器实例来使用这些证书来实现 HTTPS。非常有可能配置`svc-notes`服务来独立处理 HTTPS。在 Node.js 运行时中有一个 HTTPS 服务器对象，可以处理这个要求。在`notes/app.mjs`中进行小的重写以适应 SSL 证书来实现 HTTPS，以及 HTTP-01 挑战。

但还有另一种可能的方法。诸如 NGINX 之类的 Web 服务器非常成熟、稳健、经过充分测试，最重要的是支持 HTTPS。我们可以使用 NGINX 来处理 HTTPS 连接，并使用所谓的*反向代理*将流量传递给`svc-notes`作为 HTTP。也就是说，NGINX 将被配置为接受入站 HTTPS 流量，将其转换为 HTTP 流量发送到`svc-notes`。

除了实现 HTTPS 的安全目标之外，这还有一个额外的优势，即使用一个备受推崇的 Web 服务器（NGINX）来作为对抗某些类型攻击的屏障。

在查看了 Let's Encrypt 文档之后，我们知道了如何继续。有一个可用的 Docker 容器，可以处理我们需要在 NGINX 和 Let's Encrypt 中进行的所有操作。在下一节中，我们将学习如何将该容器与 Notes 堆栈集成，并实现 HTTPS。

## 使用 NGINX 和 Let's Encrypt 在 Docker 中为 Notes 实现 HTTPS

我们刚刚讨论了如何使用 Let's Encrypt 为 Notes 实现 HTTPS。我们将采取的方法是使用一个预先制作的 Docker 容器，Cronginx（[`hub.docker.com/r/robogeek/cronginx`](https://hub.docker.com/r/robogeek/cronginx)），其中包括 NGINX、Certbot（Let's Encrypt 客户端）和一个用于管理 SSL 证书更新的 Cron 服务器和 Cron 作业。这只需要向 Notes 堆栈添加另一个容器，进行一些配置，并运行一个命令来注册我们的域名到 Let's Encrypt。

在开始本节之前，请确保您已经设置了一个域名，我们将在这个项目中使用。

在 Cronginx 容器中，Cron 用于管理后台任务以更新 SSL 证书。是的，Cron，Linux/Unix 管理员几十年来一直用来管理后台任务的服务器。

NGINX 配置将同时处理 HTTP-01 挑战并为 HTTPS 连接使用反向代理。*代理服务器*充当中间人；它接收来自客户端的请求，并使用其他服务来满足这些请求。*反向代理*是一种从一个或多个其他服务器检索资源的代理服务器，同时使其看起来像资源来自代理服务器。在这种情况下，我们将配置 NGINX 以访问`http://svc-notes:3000`上的 Notes 服务，同时使 Notes 服务看起来是由 NGINX 代理托管的。

如果您不知道如何配置 NGINX，不用担心，因为我们将准确地展示该怎么做，而且相对简单。

### 添加 Cronginx 容器以支持 Notes 上的 HTTPS

我们已经确定，添加 HTTPS 支持需要向 Notes 堆栈添加另一个容器。这个容器将处理 HTTPS 连接，并集成用于管理从 Let's Encrypt 获取的 SSL 证书的工具。

在`compose-stack`目录中，编辑`docker-compose.yml`如下：

```

Because the `svc-notes` container will not be handling inbound traffic, we start by disabling its `ports` tag. This has the effect of ensuring it does not export any ports to the public. Instead, notice that in the `cronginx` container we export both port `80` (HTTP) and port `443` (HTTPS). That container will take over interfacing with the public internet.

Another change on `svc-notes` is to set the `TWITTER_CALLBACK_HOST` environment variable. Set this to the domain name you've chosen. Remember that correctly setting this variable is required for successful login using Twitter. Until we finish implementing HTTPS, this should have an HTTP URL.

The `deploy` tag for Cronginx is the same as for `svc-notes`. In theory, because `svc-notes` is no longer interacting with the public it could be redeployed to an EC2 instance on the private network. Because both are attached to `frontnet`, either will be able to access the other with a simple domain name reference, which we'll see in the configuration file.

This container uses the same DNS configuration, because Certbot needs to be able to reach the Let's Encrypt servers to do its work.

The final item of interest is the volume mounts. In the previous section, we discussed certain directories that must be mounted into this container. As with the database containers, the purpose is to persist the data in those directories while letting us destroy and recreate the Cronginx container as needed. Each directory is mounted from `/home/ubuntu` because that's the directory that is available on the EC2 instances. The three directories are as follows:

*   `/etc/letsencrypt`: As discussed earlier, Certbot uses this directory to track administrative information about domains being managed on the server. It also stores the SSL certificates in this directory.
*   `/webroots`: This directory will be used in satisfying the HTTP-01 request to the `http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>` URL.
*   `/etc/nginx/conf.d`: This directory holds the NGINX configuration files for each domain we'll handle using this Cronginx instance.

For NGINX configuration, there is a default config file at `/etc/nginx/nginx.conf`. That file automatically includes any configuration file in `/etc/nginx/conf.d`, within an `http` context. What that means is each such file should have one or more `server` declarations. It won't be necessary to go deeper into learning about NGINX since the config files we will use are very straightforward.

We will be examining NGINX configuration files. If you need to learn more about these files, the primary documentation is at [`nginx.org/en/docs/`](https://nginx.org/en/docs/).

Further documentation for the commercial NGINX Plus product is at [`www.nginx.com/resources/admin-guide/`](https://www.nginx.com/resources/admin-guide/).

The NXING website has a *Getting Started* section with many useful recipes at [`www.nginx.com/resources/wiki/start/`](https://www.nginx.com/resources/wiki/start/).

It will be a useful convention to follow to have one file in the `/etc/nginx/conf.d` directory for each domain you are hosting. That means, in this project, you will have one domain, and therefore you'll store one file in the directory named `YOUR-DOMAIN.conf`. For the example domain we configured earlier, that file would be `notes.geekwisdom.net.conf`.

### Creating an NGINX configuration to support registering domains with Let's Encrypt

At this point, you have selected a domain you will use for Notes. To register a domain with Let's Encrypt, we need a web server configured to satisfy requests to the `http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN>` URL, and where the corresponding directory is writable by Certbot. All the necessary elements are contained in the Cronginx container. 

What we need to do is create an NGINX configuration file suitable for handling registration, then run the shell script supplied inside Cronginx. After registration is handled, there will be another NGINX configuration file that's suitable for HTTPS. We'll go over that in a later section.

Create a file for your domain named `initial-YOUR-DOMAIN.conf`, named this way because it's the initial configuration file for the domain. It will contain this:

```

正如我们所说，NGINX 配置文件相对简单。这声明了一个服务器，本例中监听端口为`80`（HTTP）。如果需要，可以轻松开启 IPv6 支持。

`server_name`字段告诉 NGINX 要处理哪个域名。`access_log`和`error_log`字段，顾名思义，指定了日志输出的位置。

`location`块描述了如何处理域的 URL 空间的部分。在第一个块中，它表示`/.well-known` URL 上的 HTTP-01 挑战是通过从`/webroots/YOUR-DOMAIN`读取文件来处理的。我们已经在`docker-compose.yml`文件中看到了该目录的引用。

第二个`location`块描述了反向代理配置。在这种情况下，我们配置它以在端口`3000`上对`svc-notes`容器运行 HTTP 代理。这对应于`docker-compose.yml`文件中的配置。

这就是配置文件，但在部署到 swarm 之前，我们需要做一些工作。

### 在 EC2 主机上添加所需的目录

我们已经确定了三个用于 Cronginx 的目录。请记住，每个 EC2 主机都是由我们在 Terraform 文件的`user_data`字段中提供的 shell 脚本进行配置的。该脚本安装 Docker 并执行另一个设置。因此，我们应该使用该脚本来创建这三个目录。

在`terraform-swarm`中，编辑`ec2-public.tf`并进行以下更改：

```

There is an existing shell script that performs the Docker setup. These three lines are appended to that script and create the directories.

With this in place, we can redeploy the EC2 cluster, and the directories will be there ready to be used.

### Deploying the EC2 cluster and Docker swarm

Assuming that the EC2 cluster is currently not deployed, we can set it up as we did in Chapter 12, *Deploying a Docker Swarm to AWS EC2 with Terraform*. In `terraform-swarm`, run this command:

```

到目前为止，你已经做了几次这样的事情，知道该怎么做。等待部署完成，记录 IP 地址和其他数据，然后初始化 swarm 集群并设置远程控制访问，这样你就可以在笔记本上运行 Docker 命令。

一个非常重要的任务是获取 IP 地址并转到您的 DNS 注册商，更新域的 A 记录为新的 IP 地址。

我们需要将 NGINX 配置文件复制到`/home/ubuntu/nginx-conf-d`，操作如下：

```

The `chown` command is required because when Terraform created that directory it became owned by the `root` user. It needs to be owned by the `ubuntu` user for the `scp` command to work.

At this point make sure that, in `compose-swarm/docker-compose.yml`, the `TWITTER_CALLBACK_HOST` environment variable for `svc-notes` is set to the HTTP URL (`http://YOUR-DOMAIN`) rather than the HTTPS URL. Obviously you have not yet provisioned HTTPS and can only use the HTTP domain.

With those things set up, we can run this:

```

这将向 swarm 添加所需的秘密，并部署 Notes 堆栈。几分钟后，所有服务应该都已启动。请注意，Cronginx 是其中之一。

一旦完全启动，您应该能够像以往一样使用 Notes，但使用您配置的域名。您甚至可以使用 Twitter 登录。

### 使用 Let's Encrypt 注册域名

我们刚刚在 AWS EC2 基础设施上部署了 Notes 堆栈。这次部署的一部分是 Cronginx 容器，我们将用它来处理 HTTPS 配置。

我们已经在 swarm 上部署了 Notes，`cronginx`容器充当 HTTP 代理。在该容器内预先安装了 Certbot 工具和一个脚本（`register.sh`）来帮助注册域名。我们必须在`cronginx`容器内运行`register.sh`，一旦域名注册完成，我们将需要上传一个新的 NGINX 配置文件。

在`cronginx`容器内启动 shell 可能会很容易：

```

You see there is a file named `register.sh` containing the following:

```

该脚本旨在创建`/webroots`中所需的目录，并使用 Certbot 注册域名并提供 SSL 证书。参考配置文件，您将看到`/webroots`目录的使用方式。

`certbot certonly`命令只检索 SSL 证书，不会在任何地方安装它们。这意味着它不会直接集成到任何服务器中，而只是将证书存储在一个目录中。该目录位于`/etc/letsencrypt`层次结构内。

`--webroot`选项意味着我们正在与现有的 Web 服务器合作。必须配置它以从指定为`-w`选项的目录中提供`/.well-known/acme-challenge`文件，这就是我们刚刚讨论过的`/webroots/YOUR-DOMAIN`目录。`-d`选项是要注册的域名。

简而言之，`register.sh`与我们创建的配置文件相匹配。

脚本的执行方式如下：

```

We run the shell script using `sh -x register.sh` and supply our chosen domain name as the first argument. Notice that it creates the `/webroots` directory, which is required for the Let's Encrypt validation. It then runs `certbot certonly`, and the tool starts asking questions required for registering with the service.

The registration process ends with this message:

```

关键数据是构成 SSL 证书的两个 PEM 文件的路径名。它还告诉您定期运行`certbot renew`来更新证书。我们已经通过安装 Cron 作业来处理了这个问题。

正如他们所说，将这个目录持久化存储在其他地方是很重要的。我们已经采取了第一步，将其存储在容器外部，这样我们可以随意销毁和重新创建容器。但是当需要销毁和重新创建 EC2 实例时怎么办？在您的待办事项中安排一个任务来设置备份程序，然后在 EC2 集群初始化期间从备份中安装这个目录。

现在我们的域名已经注册到 Let's Encrypt，让我们修改 NGINX 配置以支持 HTTPS。

## 使用 Let's Encrypt 证书实现 NGINX HTTPS 配置

好了，我们离加密如此之近，我们可以感受到它的味道。我们已经将 NGINX 和 Let's Encrypt 工具部署到了笔记应用程序堆栈中。我们已经验证了仅支持 HTTP 的 NGINX 配置是否正确。我们已经使用 Certbot 为 HTTPS 从 Let's Encrypt 提供 SSL 证书。现在是时候重写 NGINX 配置以支持 HTTPS，并将该配置部署到笔记堆栈中。

在`compose-stack/cronginx`中创建一个新文件，`YOUR-DOMAIN.conf`，例如`notes.geekwisdom.net.conf`。之前的文件有一个前缀`initial`，因为它在实现 HTTPS 的初始阶段为我们提供了服务。现在域名已经注册到 Let's Encrypt，我们需要一个不同的配置文件：

```

This reconfigures the HTTP server to do permanent redirects to the HTTPS site. When an HTTP request results in a 301 status code, that is a permanent redirect. Any redirect tells web browsers to visit a URL provided in the redirect. There are two kinds of redirects, temporary and permanent, and the 301 code makes this a permanent redirect. For permanent redirects, the browser is supposed to remember the redirect and apply it in the future. In this case, the redirect URL is computed to be the request URL, rewritten to use the HTTPS protocol.

Therefore our users will silently be sent to the HTTPS version of Notes, with no further effort on our part.

To implement the HTTPS server, add this to the config file:

```

这是 NGINX 中的 HTTPS 服务器实现。与 HTTP 服务器声明有许多相似之处，但也有一些特定于 HTTPS 的项目。它在端口`443`上监听，这是 HTTPS 的标准端口，并告诉 NGINX 使用 SSL。它具有相同的服务器名称和日志配置。

下一部分告诉 NGINX SSL 证书的位置。只需用 Certbot 给出的路径名替换它。

下一部分处理了`/.well-known`的 URL，用于将来使用 Let's Encrypt 进行验证请求。HTTP 和 HTTPS 服务器定义都已配置为从同一目录处理此 URL。我们不知道 Let's Encrypt 是否会通过 HTTP 或 HTTPS URL 请求验证，因此我们可能会在两个服务器上都支持这一点。

下一部分是一个代理服务器，用于处理`/socket.io`的 URL。这需要特定的设置，因为 Socket.IO 必须从 HTTP/1.1 升级到 WebSocket。否则，JavaScript 控制台会打印错误，并且 Socket.IO 功能将无法工作。有关更多信息，请参见代码中显示的 URL。

最后一部分是设置一个反向代理，将 HTTPS 流量代理到运行在端口`3000`上的 HTTP 后端服务器上的笔记应用程序。

创建了一个新的配置文件后，我们可以将其上传到`notes-public` EC2 实例中，方法如下：

```

The next question is how do we restart the NGINX server so it reads the new configuration file? One way is to send a SIGHUP signal to the NGINX process, causing it to reload the configuration:

```

`nginx.pid`文件包含 NGINX 进程的进程 ID。许多 Unix/Linux 系统上的后台服务都将进程 ID 存储在这样的文件中。这个命令向该进程发送 SIGHUP 信号，NGINX 在接收到该信号时会重新读取其配置。SIGHUP 是标准的 Unix/Linux*信号*之一，通常用于导致后台进程重新加载其配置。有关更多信息，请参见`signal(2)`手册页。

但是，使用 Docker 命令，我们可以这样做：

```

That will kill the existing container and start a new one.

Instead of that rosy success message, you might get this instead:

```

这表示 Docker swarm 看到容器退出了，因此无法重新启动服务。

在 NGINX 配置文件中很容易出错。首先仔细查看配置，看看可能出了什么问题。诊断的下一阶段是查看 NGINX 日志。我们可以使用`docker logs`命令来做到这一点，但我们需要知道容器的名称。因为容器已经退出，我们必须运行这个命令：

```

The `-a` option causes `docker ps` to return information about every container, even the ones that are not currently running. With the container name in hand, we can run this:

```

事实上，问题是语法错误，它甚至会友好地告诉您行号。

一旦您成功重新启动了`cronginx`服务，请访问您部署的 Notes 服务并验证它是否处于 HTTPS 模式。

在本节中，我们成功地为基于 AWS EC2 的 Docker 集群部署了 Notes 应用程序堆栈的 HTTPS 支持。我们使用了上一节中创建的 Docker 容器文件，并将更新后的 Notes 堆栈部署到了集群中。然后我们运行 Certbot 来注册我们的域名并使用 Let's Encrypt。然后我们重写了 NGINX 配置以支持 HTTPS。

我们的下一个任务是验证 HTTPS 配置是否正常工作。

## 测试 Notes 应用程序的 HTTPS 支持

在本书中，我们对 Notes 进行了临时测试和更正式的测试。因此，您知道要确保 Notes 在这个新环境中正常工作需要做什么。但是还有一些特定于 HTTPS 的事项需要检查。

在浏览器中，转到您托管应用程序的域名。如果一切顺利，您将会看到应用程序，并且它将自动重定向到 HTTPS 端口。

为了让我们人类知道网站是在 HTTPS 上，大多数浏览器在地址栏中显示一个*锁*图标。

您应该能够单击该锁图标，浏览器将显示一个对话框，提供有关证书的信息。证书将验证这确实是正确的域，并且还将显示证书是由 Let's Encrypt 通过**Let's Encrypt Authority X3**颁发的。

您应该能够浏览整个应用程序并仍然看到锁图标。

您应该注意*mixed content*警告。这些警告将出现在 JavaScript 控制台中，当 HTTPS 加载的页面上的某些内容使用 HTTP URL 加载时会出现。混合内容场景不够安全，因此浏览器会向用户发出警告。消息可能会出现在浏览器内的 JavaScript 控制台中。如果您正确地按照本书中的说明操作，您将不会看到此消息。

最后，前往 Qualys SSL Labs SSL 实现测试页面。该服务将检查您的网站，特别是 SSL 证书，并为您提供一个分数。要检查您的分数，请参阅[`www.ssllabs.com/ssltest/`](https://www.ssllabs.com/ssltest/)。

完成了这项任务后，您可能希望关闭 AWS EC2 集群。在这样做之前，最好先从 Let's Encrypt 中注销域名。这也只需要运行带有正确命令的 Certbot：

```

As before, we run `docker ps` to find out the exact container name. With that name, we start a command shell inside the container. The actual act is simple, we just run `certbot delete` and specify the domain name.

Certbot doesn't just go ahead and delete the registration. Instead, it asks you to verify that's what you want to do, then it deletes the registration.

In this section, we have finished implementing HTTPS support for Notes by learning how to test that it is implemented correctly.

We've accomplished a redesign of the Notes application stack using a custom NGINX-based container to implement HTTPS support. This approach can be used for any service deployment, where an NGINX instance is used as the frontend to any kind of backend service.

But we have other security fish to fry. Using HTTPS solves only part of the security problem. In the next section, we'll look at Helmet, a tool for Express applications to set many security options in the HTTP headers.

# Using Helmet for across-the-board security in Express applications

While it was useful to implement HTTPS, that's not the end of implementing security measures. It's hardly the beginning of security, for that matter. The browser makers working with the standards organizations have defined several mechanisms for telling the browser what security measures to take. In this section, we will go over some of those mechanisms, and how to implement them using Helmet.

Helmet ([`www.npmjs.com/package/helmet`](https://www.npmjs.com/package/helmet)) is, as the development team says, not a security silver bullet (do Helmet's authors think we're trying to protect against vampires?). Instead, it is a toolkit for setting various security headers and taking other protective measures in Node.js applications. It integrates with several packages that can be either used independently or through Helmet.

Using Helmet is largely a matter of importing the library into `node_modules`, making a few configuration settings, and integrating it with Express.

In the `notes` directory, install the package like so:

```

然后将此添加到`notes/app.mjs`中：

```

That's enough for most applications. Using Helmet out of the box provides a reasonable set of default security options. We could be done with this section right now, except that it's useful to examine closely what Helmet does, and its options.

Helmet is actually a cluster of 12 modules for applying several security techniques. Each can be individually enabled or disabled, and many have configuration settings to make. One option is instead of using that last line, to initialize and configure the sub-modules individually. That's what we'll do in the following sections.

## Using Helmet to set the Content-Security-Policy header

The **Content-Security-Policy** (**CSP**) header can help to protect against injected malicious JavaScript and other file types.

We would be remiss to not point out a glaring problem with services such as the Notes application. Our users could enter any code they like, and an improperly behaving application will simply display that code. Such applications can be a vector for JavaScript injection attacks among other things.

To try this out, edit a note and enter something like this:

```

单击保存按钮，您将看到此代码显示为文本。Notes 的危险版本将在 notes 视图页面中插入`<script>`标签，以便加载恶意 JavaScript 并为访问者造成问题。相反，`<script>`标签被编码为安全的 HTML，因此它只会显示为屏幕上的文本。我们并没有为这种行为做任何特殊处理，Handlebars 为我们做了这个。

实际上，这更有趣一些。如果我们查看 Handlebars 文档，[`handlebarsjs.com/expressions.html`](http://handlebarsjs.com/expressions.html)，我们会了解到这个区别：

```

In Handlebars, a value appearing in a template using two curly braces (`{{encoded}}`) is encoded using HTML coding. For the previous example, the angle bracket is encoded as `&lt;` and so on for display, rendering that JavaScript code as neutral text rather than as HTML elements. If instead, you use three curly braces (`{{{notEncoded}}}`), the value is not encoded and is instead presented as is. The malicious JavaScript would be executed in your visitor's browser, causing problems for your users.

We can see this problem by changing `views/noteview.hbs` to use raw HTML output:

```

我们不建议这样做，除非作为一个实验来看看会发生什么。效果是，正如我们刚才说的，允许用户输入 HTML 代码并将其原样显示。如果 Notes 以这种方式行事，任何笔记都可能携带恶意 JavaScript 片段或其他恶意软件。

让我们回到 Helmet 对 Content-Security-Policy 头的支持。有了这个头部，我们指示 Web 浏览器可以从哪个范围下载某些类型的内容。具体来说，它让我们声明浏览器可以从哪些域下载 JavaScript、CSS 或字体文件，以及浏览器允许连接哪些域进行服务。

因此，这个标头解决了所命名的问题，即我们的用户输入恶意 JavaScript 代码。但它还处理了恶意行为者入侵并修改模板以包含恶意 JavaScript 代码的类似风险。在这两种情况下，告诉浏览器特定的允许域名列表意味着恶意网站的 JavaScript 引用将被阻止。从`pirates.den`加载的恶意 JavaScript 不会运行。

要查看此 Helmet 模块的文档，请参阅[`helmetjs.github.io/docs/csp/`](https://helmetjs.github.io/docs/csp/)。

有很多选项。例如，您可以导致浏览器将任何违规行为报告给您的服务器，这样您就需要为`/report-violation`实现一个路由处理程序。这段代码对 Notes 来说已经足够了：

```

For better or for worse, the Notes application implements one security best practice—all CSS and JavaScript files are loaded from the same server as the application. Therefore, for the most part, we can use the `'self'` policy. There are several exceptions:

*   `scriptSrc`: Defines where we are allowed to load JavaScript. We do use inline JavaScript in `noteview.hbs` and `index.hbs`, which must be allowed.
*   `styleSrc`, `fontSrc`: We're loading CSS files from both the local server and from Google Fonts.
*   `connectSrc`: The WebSockets channel used by Socket.IO is declared here.

To develop this, we can open the JavaScript console or Chrome DevTools while browsing the website. Errors will show up listing any domains of failed download attempts. Simply add such domains to the configuration object.

### Making the ContentSecurityPolicy configurable

Obviously, the ContentSecurityPolicy settings shown here should be configurable. If nothing else the setting for `connectSrc` must be, because it can cause a problem that prevents Socket.IO from working. As shown here, the `connectSrc` setting includes the URL `wss://notes.geekwisdom.net`. The `wss` protocol here refers to WebSockets and is designed to allow Socket.IO to work while Notes is hosted on `notes.geekwisdom.net`. But what about when we want to host it on a different domain?

To experiment with this problem, change the hard coded string to a different domain name then redeploy it to your server. In the JavaScript console in your browser you will get an error like this:

```

发生的情况是，静态定义的常量不再与 Notes 部署的域兼容。您已重新配置此设置，以限制连接到不同域，例如`notes.newdomain.xyz`，但服务仍托管在现有域，例如`notes.geekwisdom.net`。浏览器不再相信连接到`notes.geekwisdom.net`是安全的，因为您的配置说只信任`notes.newdomain.xyz`。

最好的解决方案是通过声明另一个环境变量来使其成为可配置的设置，以便根据需要进行设置以自定义行为。

在`app.mjs`中，将`contentSecurityPolicy`部分更改为以下内容：

```

This lets us define an environment variable, `CSP_CONNECT_SRC_URL`, which will supply a URL to be added into the array passed to the `connectSrc` parameter. Otherwise, the `connectSrc` setting will be limited to `"'self'"`.

Then in `compose-swarm/docker-compose.yml`, we can declare that variable like so:

```

我们现在可以在配置中设置它，根据需要进行更改。

重新运行`docker stack deploy`命令后，错误消息将消失，Socket.IO 功能将开始工作。

在本节中，我们了解了网站向浏览器发送恶意脚本的潜力。接受用户提供内容的网站，如 Notes，可能成为恶意软件的传播途径。通过使用这个标头，我们能够通知网络浏览器在访问这个网站时信任哪些域名，从而阻止任何恶意内容被恶意第三方添加。

接下来，让我们学习如何防止过多的 DNS 查询。

## 使用头盔设置 X-DNS-Prefetch-Control 标头

DNS Prefetch 是一些浏览器实现的一种便利，其中浏览器将预先为给定页面引用的域名进行 DNS 请求。如果页面有指向其他网站的链接，它将为这些域名进行 DNS 请求，以便填充本地 DNS 缓存。这对用户很好，因为它提高了浏览器的性能，但它也是一种侵犯隐私的行为，并且可能使人看起来好像访问了他们没有访问的网站。有关文档，请参阅[`helmetjs.github.io/docs/dns-prefetch-control`](https://helmetjs.github.io/docs/dns-prefetch-control)。

使用以下内容设置 DNS 预取控制：

```

In this case, we learned about preventing the browser from making premature DNS queries. The risk is that excess DNS queries give a false impression of which websites someone has visited.

Let's next look at how to control which browser features can be enabled.

## Using Helmet to control enabled browser features using the Feature-Policy header

Web browsers nowadays have a long list of features that can be enabled, such as vibrating a phone, or turning on the camera or microphone, or reading the accelerometer. These features are interesting and very useful in some cases, but can be used maliciously. The Feature-Policy header lets us notify the web browser about which features to allow to be enabled, or to deny enabling.

For Notes we don't need any of those features, though some look intriguing as future possibilities. For instance, we could pivot to taking on Instagram if we allowed people to upload photos, maybe? In any case, this configuration is very strict:

```

要启用一个功能，要么将其设置为`'self'`以允许网站启用该功能，要么将其设置为第三方网站的域名，以允许启用该功能。例如，启用支付功能可能需要添加`'paypal.com'`或其他支付处理器。

在本节中，我们学习了允许启用或禁用浏览器功能。

在下一节中，让我们学习如何防止点击劫持。

## 使用头盔设置 X-Frame-Options 标头

**点击劫持**与劫持汽车无关，而是一种巧妙的技术，用于诱使人们点击恶意内容。这种攻击使用一个包含恶意代码的不可见`<iframe>`，放置在看起来诱人点击的东西上。然后用户会被诱使点击恶意内容。

Helmet 的`frameguard`模块将设置一个标头，指示浏览器如何处理`<iframe>`。有关文档，请参阅[`helmetjs.github.io/docs/frameguard/`](https://helmetjs.github.io/docs/frameguard/)。

```

This setting controls which domains are allowed to put this page into an `<iframe>`. Using `deny`, as shown here, prevents all sites from embedding this content using an `<iframe>`. Using `sameorigin` allows the site to embed its own content. We can also list a single domain name to be allowed to embed this content.

In this section, you have learned about preventing our content from being embedded into another website using `<iframe>`.

Now let's learn about hiding the fact that Notes is powered by Express.

## Using Helmet to remove the X-Powered-By header

The `X-Powered-By` header can give malicious actors a clue about the software stack in use, informing them of attack algorithms that are likely to succeed. The Hide Powered-By submodule for Helmet simply removes that header.

Express can disable this feature on its own:

```

或者您可以使用 Helmet 来这样做：

```

Another option is to masquerade as some other stack like so:

```

没有什么比让坏人迷失方向更好的了。

我们已经学会了如何让您的 Express 应用程序隐身，以避免给坏人提供关于如何闯入的线索。接下来让我们学习一下如何声明对 HTTPS 的偏好。

## 通过严格传输安全性改进 HTTPS

在实现了 HTTPS 支持之后，我们还没有完全完成。正如我们之前所说的，最好让我们的用户使用 Notes 的 HTTPS 版本。在我们的 AWS EC2 部署中，我们强制用户使用 HTTPS 进行重定向。但在某些情况下，我们无法这样做，而必须试图鼓励用户访问 HTTPS 站点而不是 HTTP 站点。

严格传输安全性标头通知浏览器应该使用站点的 HTTPS 版本。由于这只是一个通知，还需要实现从 HTTP 到 HTTPS 版本的重定向。

我们设置严格传输安全性如下：

```

This tells the browser to stick with the HTTPS version of the site for the next 60 days, and never visit the HTTP version.

And, as long as we're on this issue, let's learn about `express-force-ssl`, which is another way to implement a redirect so the users use HTTPS. After adding a dependency to that package in `package.json`, add this in `app.mjs`:

```

安装了这个软件包后，用户不必被鼓励使用 HTTPS，因为我们在默默地强制他们这样做。

在我们在 AWS EC2 上的部署中，使用这个模块会导致问题。因为 HTTPS 是在负载均衡器中处理的，Notes 应用程序不知道访问者正在使用 HTTPS。相反，Notes 看到的是一个 HTTP 连接，如果使用了`forceSSL`，它将强制重定向到 HTTPS 站点。但是因为 Notes 根本没有看到 HTTPS 会话，它只看到 HTTP 请求，而`forceSSL`将始终以重定向方式响应。

这些设置并非在所有情况下都有用。您的环境可能需要这些设置，但对于像我们在 AWS EC2 上部署的环境来说，这根本不需要。对于这些有用的站点，我们已经了解到如何通知 Web 浏览器使用我们网站的 HTTPS 版本，以及如何强制重定向到 HTTPS 站点。

接下来让我们学习一下**跨站脚本**（**XSS**）攻击。

## 使用 Helmet 减轻 XSS 攻击

XSS 攻击试图将 JavaScript 代码注入到网站输出中。通过在另一个网站中注入恶意代码，攻击者可以访问他们本来无法检索的信息，或者引起其他类型的麻烦。 X-XSS-Protection 标头可以防止某些 XSS 攻击，但并非所有类型的 XSS 攻击，因为 XSS 攻击有很多种类型：

```

This causes an X-XSS-Protection header to be sent specifying `1; mode=block`. This mode tells the browser to look for JavaScript in the request URL that also matches JavaScript on the page, and it then blocks that code. This is only one type of XSS attack, and therefore this is of limited usefulness. But it is still useful to have this enabled.

In this section, we've learned about using Helmet to enable a wide variety of security protections in web browsers. With these settings, our application can work with the browser to avoid a wide variety of attacks, and therefore make our site significantly safer.

But with this, we have exhausted what Helmet provides. In the next section, we'll learn about another package that prevents cross-site request forgery attacks.

# Addressing Cross-Site Request Forgery (CSRF) attacks

CSRF attacks are similar to XSS attacks in that both occur across multiple sites. In a CSRF attack, malicious software forges a bogus request on another site. To prevent such an attack, CSRF tokens are generated for each page view. The tokens are to be included as hidden values in HTML FORMs and then checked when the FORM is submitted. A mismatch on the tokens causes the request to be denied.

The `csurf` package is designed to be used with Express [`www.npmjs.com/package/csurf`](https://www.npmjs.com/package/csurf) . In the `notes` directory, run this:

```

这将安装`csurf`软件包，并在`package.json`中记录依赖关系。

然后像这样安装中间件：

```

The `csurf` middleware must be installed following the `cookieParser` middleware.

Next, for every page that includes a FORM, we must generate and send a token with the page. That requires two things, in the `res.render` call we generate the token, sending the token with other data for the page, and then in the view template we include the token as a hidden INPUT on any form in the page. We're going to be touching on several files here, so let's get started.

In `routes/notes.mjs,` add the following as a parameter to the `res.render` call for the `/add`, `/edit`, `/view`, and `/destroy` routes:

```

这将生成 CSRF 令牌，确保它与其他数据一起发送到模板。同样，在`routes/users.mjs`中的`/login`路由也要这样做。我们的下一个任务是确保相应的模板将令牌呈现为隐藏的输入。 

在`views/noteedit.hbs`和`views/notedestroy.hbs`中，添加以下内容：

```

This is a hidden INPUT, and whenever the FORM containing this is submitted this value will be carried along with the FORM parameters.

The result is that code on the server generates a token that is added to each FORM. By adding the token to FORMs, we ensure it is sent back to the server on FORM submission. Other software on the server can then match the received token to the tokens that have been sent. Any mismatched token will cause the request to be rejected.

In `views/login.hbs`, make the same addition but adding it inside the FORM like so:

```

在`views/noteview.hbs`中，有一个用于提交评论的表单。做出以下更改：

```

In every case, we are adding a hidden INPUT field. These fields are not visible to the user and are therefore useful for carrying a wide variety of data that will be useful to receive on the server. We've already used hidden INPUT fields in Notes, such as in `noteedit.hbs` for the `docreate` flag.

This `<input>` tag renders the CSRF token into the FORM. When the FORM is submitted, the `csurf` middleware checks it for the correctness and rejects any that do not match.

In this section, we have learned how to stop an important type of attack, CSRF.

# Denying SQL injection attacks

SQL injection is another large class of security exploits, where the attacker puts SQL commands into input data. See [`www.xkcd.com/327/`](https://www.xkcd.com/327/) for an example.

The best practice for avoiding this problem is to use parameterized database queries, allowing the database driver to prevent SQL injections simply by correctly encoding all SQL parameters. For example, we do this in the SQLite3 model:

```

这使用了一个参数化字符串，`key`的值被编码并插入到问号的位置。大多数数据库驱动程序都有类似的功能，并且它们已经知道如何将值编码到查询字符串中。即使坏人将一些 SQL 注入到`key`的值中，因为驱动程序正确地对`key`的内容进行了编码，最坏的结果也只是一个 SQL 错误消息。这自动使任何尝试的 SQL 注入攻击无效。

与我们本可以编写的另一种选择形成对比：

```

The template strings feature of ES6 is very tempting to use everywhere. But it is not appropriate in all circumstances. In this case, the database query parameter would not be screened nor encoded, and if a miscreant can get a custom string to that query it could cause havoc in the database.

In this section, we learned about SQL injection attacks. We learned that the best defense against this sort of attack is the coding practice all coders should follow anyway, namely to use parameterized query methods offered by the database driver.

In the next section, we will learn about an effort in the Node.js community to screen packages for vulnerabilities.

# Scanning for known vulnerabilities in Node.js packages

Built-in to the npm command-line tool is a command, `npm audit`, for reporting known vulnerabilities in the dependencies of your application. To support this command is a team of people, and software, who scan packages added to the npm registry. Every third-party package used by your application is a potential security hole.

It's not just that a query against the application might trigger buggy code, whether in your code or third-party packages. In some cases, packages that explicitly cause harm have been added to the npm registry.

Therefore the security audits of packages in the npm registry are extremely helpful to every Node.js developer.

The `audit` command consults the vulnerability data collected by the auditing team and tells you about vulnerabilities in packages your application uses.

When running `npm install`, the output might include a message like this:

```

这告诉我们，当前安装的软件包中有八个已知的漏洞。每个漏洞在这个规模上被分配了一个严重性等级（[`docs.npmjs.com/about-audit-reports`](https://docs.npmjs.com/about-audit-reports)）：

+   *严重*: 立即处理

+   *高*: 尽快处理

+   *中等*: 尽可能快地处理

+   *低*: 自行处理

在这种情况下，运行`npm audit`告诉我们，所有低优先级问题都在`minimist`软件包中。例如，报告中包括了这样的内容：

```

In this case, `minimist` is reported because `hbs` uses `handlebars`, which uses `optimist`, which uses `minimist`. There are six more instances where `minimist` is used by some package that's used by another package that our application is using.

In this case, we're given a recommendation, to upgrade to `hbs@4.1.1`, because that release results in depending on the correct version of `minimist`.

In another case, the chain of dependencies is this:

```

在这种情况下，没有推荐的修复方法，因为这些软件包都没有发布依赖于正确版本的`minimist`的新版本。这种情况的推荐解决方案是向每个相应的软件包团队提交问题，要求他们将其依赖项更新为有问题软件包的后续版本。

在最后一种情况下，是我们的应用直接依赖于有漏洞的软件包：

```

Therefore it is our responsibility to fix this problem because it is in our code. The good news is that this particular package is not executed on the server side since jQuery is a client-side library that just so happens to be distributed through the npm repository.

The first step is to read the advisory to learn what the issue is. That way, we can evaluate for ourselves how serious this is, and what we must do to correctly fix the problem.

What's not recommended is to blindly update to a later package release just because you're told to do so. What if the later release is incompatible with your application? The best practice is to test that the update does not break your code. You may need to develop tests that illustrate the vulnerability. That way, you can verify that updating the package dependency fixes the problem.

In this case, the advisory says that jQuery releases before 3.5.0 have an XSS vulnerability. We are using jQuery in Notes because it is required by Bootstrap, and on the day we read the Bootstrap documentation we were told to use a much earlier jQuery release. Today, the Bootstrap documentation says to use jQuery 3.5.1\. That tells us the Bootstrap team has already tested against jQuery 3.5.1, and we are therefore safe to go ahead with updating the dependency.

In this section, we have learned about the security vulnerability report we can get from the npm command-line tool. Unfortunately for Yarn users, it appears that Yarn doesn't support this command. In any case, this is a valuable resource for being warned about known security issues.

In the next section, we'll learn about the best practices for cookie management in Express applications.

# Using good cookie practices

Some nutritionists say eating too many sweets, such as cookies, is bad for your health. Web cookies, however, are widely used for many purposes including recording whether a browser is logged in or not. One common use is for cookies to store session data to aid in knowing whether someone is logged in or not.

In the Notes application, we're already following the good practices described in the Express security guidelines:

*   We're using an Express session cookie name different from the default shown in the documentation.
*   The Express session cookie secret is not the default shown in the documentation.
*   We use the `express-session` middleware, which only stores a session ID in the cookie, rather than the whole session data object.

Taken together, an attacker can't exploit any known vulnerability that relies on the default values for these items. While it is convenient that many software products have default values, such as passwords, those defaults could be security vulnerabilities. For example, the default Raspberry Pi login/password is *pi* and *raspberry*. While that's cute, any Raspbian-based IoT device that's left with the default login/password is susceptible to attack.

But there is more customization we can do to the cookie used with `express-session`. That package has a few options available for improving security. See [`www.npmjs.com/package/express-session`](https://www.npmjs.com/package/express-session), and then consider this change to the configuration:

```

这些是看起来有用的额外属性。`secure`属性要求 Cookie 只能通过 HTTPS 连接发送。这确保了 Cookie 数据通过 HTTPS 加密进行加密。`maxAge`属性设置了 Cookie 有效的时间，以毫秒表示。

Cookie 在 Web 浏览器中是一个非常有用的工具，即使有很多对网站如何使用 Cookie 的过度炒作的担忧。与此同时，滥用 Cookie 并造成安全问题是可能的。在这一部分，我们学习了如何通过会话 Cookie 来减轻风险。

在下一节中，我们将回顾 AWS ECS 部署的最佳实践。

# 加固 AWS EC2 部署

还有一个问题留在了第十二章中，*使用 Terraform 在 AWS EC2 上部署 Docker Swarm*，即 EC2 实例的安全组配置。我们配置了具有宽松安全组的 EC2 实例，最好是严格定义它们。我们当时确实描述了这不是最佳实践，并承诺稍后解决这个问题。这就是我们要做的地方。

在 AWS 中，要记住安全组描述了一个*防火墙*，根据 IP 端口和 IP 地址允许或禁止流量。这个工具存在是为了减少不法分子获取我们系统非法访问的潜在攻击面。

对于`ec2-public-sg`安全组，编辑`ec2-public.tf`并将其更改为以下内容：

```

This declares many specific network ports used for specific protocols. Each rule names the protocol in the `description` attribute. The `protocol` attribute says whether it is a UDP or TCP protocol. Remember that TCP is a stream-oriented protocol that ensures packets are delivered, and UDP, by contrast, is a packet-oriented protocol that does not ensure delivery. Each has characteristics making them suitable for different purposes.

Something missing is an `ingress` rule for port `3306`, the MySQL port. That's because the `notes-public` server will not host a MySQL server based on the placement constraints.

Another thing to note is which rules allow traffic from public IP addresses, and which limit traffic to IP addresses inside the VPC. Many of these ports are used in support of the Docker swarm, and therefore do not need to communicate anywhere but other hosts on the VPC.

An issue to ponder is whether the SSH port should be left open to the entire internet. If you, or your team, only SSH into the VPC from a specific network, such as an office network, then this setting could list that network. And because the `cidr_blocks` attribute takes an array, it's possible to configure a list of networks, such as a company with several offices each with their own office network.

In `ec2-private.tf`, we must make a similar change to `ec2-private-sg`:

```

这基本上是相同的，但有一些具体的区别。首先，因为私有 EC2 实例可以有 MySQL 数据库，我们声明了端口`3306`的规则。其次，除了一个规则外，所有规则都限制流量到 VPC 内的 IP 地址。

在这两个安全组定义之间，我们严格限制了 EC2 实例的攻击面。这将在任何不法分子试图侵入 Notes 服务时设置一定的障碍。

虽然我们已经为 Notes 服务实施了几项安全最佳实践，但总是还有更多可以做的。在下一节中，我们将讨论如何获取更多信息。

# AWS EC2 安全最佳实践

在设计 Notes 应用程序堆栈部署的开始，我们描述了一个应该导致高度安全部署的安全模型。我们是那种可以在餐巾纸背面设计安全部署基础设施的安全专家吗？可能不是。但 AWS 团队确实雇佣了具有安全专业知识的工程师。当我们转向 AWS EC2 进行部署时，我们了解到它提供了一系列我们在原始计划中没有考虑到的安全工具，最终我们得到了一个不同的部署模型。

在这一部分，让我们回顾一下我们做了什么，还要回顾一些 AWS 上可用的其他工具。

AWS **虚拟私有云** (**VPC**) 包含许多实现安全功能的方法，我们使用了其中的一些：

+   *安全组*充当一个严格控制进出受安全组保护的事物流量的防火墙。安全组附加到我们使用的每个基础设施元素上，在大多数情况下，我们配置它们只允许绝对必要的流量。

+   我们确保数据库实例是在 VPC 内创建的，而不是托管在公共互联网上。这样可以将数据库隐藏起来，避免公共访问。

虽然我们没有实施最初设想的分割，但围绕 Notes 的屏障足够多，应该相对安全。

在审查 AWS VPC 安全文档时，还有一些其他值得探索的设施。

AWS 虚拟私有云中的安全性：[`docs.aws.amazon.com/vpc/latest/userguide/security.html`](https://docs.aws.amazon.com/vpc/latest/userguide/security.html)。

在本节中，您有机会审查部署到 AWS ECS 的应用程序的安全性。虽然我们做得相当不错，但还有更多可以利用 AWS 提供的工具来加强应用程序的内部安全性。

有了这些，现在是时候结束本章了。

# 总结

在本章中，我们涵盖了一个非常重要的主题，应用程序安全。由于 Node.js 和 Express 社区的辛勤工作，我们能够通过在各处添加一些代码来配置安全模块，从而加强安全性。

我们首先启用了 HTTPS，因为这是现在的最佳实践，并且对我们的用户有积极的安全收益。通过 HTTPS，浏览器会对网站进行身份验证。它还可以防止中间人安全攻击，并加密用于在互联网上传输的通信，防止大部分窥探。

`helmet`包提供了一套工具，用于设置安全头，指示 Web 浏览器如何处理我们的内容。这些设置可以防止或减轻整类安全漏洞。通过`csurf`包，我们能够防止跨站点请求伪造（CSRF）攻击。

这些几个步骤是确保 Notes 应用程序安全的良好开端。但是你不应该就此止步，因为有一系列永无止境的安全问题需要解决。我们任何人都不能忽视我们部署的应用程序的安全性。

在本书的过程中，旅程是关于学习开发和部署 Node.js 网络应用程序所需的主要生命周期步骤。这始于使用 Node.js 的基础知识，然后是应用程序概念的开发，然后我们涵盖了开发、测试和部署应用程序的每个阶段。

在整本书中，我们学习了高级 JavaScript 功能，如异步函数和 ES6 模块在 Node.js 应用程序中的使用。为了存储我们的数据，我们学习了如何使用几种数据库引擎，以及一种使在不同引擎之间轻松切换的方法。

在当今的环境中，移动优先开发非常重要，为了实现这一目标，我们学习了如何使用 Bootstrap 框架。

实时通信在各种网站上都是期望的，因为先进的 JavaScript 功能意味着我们现在可以在网络应用程序中提供更多的互动服务。为了实现这一目标，我们学习了如何使用 Socket.IO 实时通信框架。

将应用程序服务部署到云主机是被广泛使用的，既可以简化系统设置，也可以扩展服务以满足用户需求。为了实现这一目标，我们学会了使用 Docker，然后学会了如何使用 Terraform 将 Docker 服务部署到 AWS ECS。我们不仅在生产部署中使用 Docker，还用它来部署测试基础设施，其中我们可以运行单元测试和功能测试。
