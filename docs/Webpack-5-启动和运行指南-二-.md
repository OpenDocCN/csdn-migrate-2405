# Webpack 5 启动和运行指南（二）

> 原文：[`zh.annas-archive.org/md5/D84E54A317E3F5B84C857CD1B0FA20B6`](https://zh.annas-archive.org/md5/D84E54A317E3F5B84C857CD1B0FA20B6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：API、插件和加载器

**应用程序编程接口**（**API**）通常用于远程站点程序之间的接口，例如当公司通过移动应用程序部分访问其网站功能作为集成系统的一部分时。

Webpack 旨在编译和优化本地化代码，因此了解本地化代码和外部 API 之间的区别对于操作软件至关重要。

插件和加载器类似。加载器基本上指示 Webpack 如何处理与更不寻常的编程语言和捆绑相关的特定任务。加载器通常由用户社区开发，而不是内部 Webpack 开发人员开发。另一方面，插件提供了一些加载器目前不提供的过程，因此在其操作上比加载器更通用。本章将在课程中提供每个功能的简明解释和详细示例。

Webpack 5 提供了丰富的插件接口。Webpack 中的大多数功能都使用这个插件接口，使得 Webpack 非常灵活。

本章将探讨插件、加载器和 API，以及每个的重要性以及每个功能在 Webpack 操作中的作用。

本章讨论的主题如下：

+   加载器

+   API

+   插件

# 加载器

加载器对于 Webpack 是基础的，其中许多加载器使得更多功能成为可能，特别是对于不是原生 ECMAScript 的脚本和框架，比如 JavaScript 和 JSON。

本章旨在为您提供可用加载器的广泛概述，以及您可能需要购买的一些加载器。当处理与您的项目特定的显著或独特的代码时，您应该搜索 Webpack 在线注册表，以确保代码可以被转译。

特别是，本节将讨论以下加载器：

+   `cache-loader`

+   `coffee-loader`

+   `coffee-redux-loader`

+   `worker-loader`

+   `cover.js`

+   `i18n-loader`

+   `imports-loader`

+   `polymer-webpack-loader`

+   `script-loader`

+   `source-map-loader`

+   `less-loader`

我们将讨论并举例说明每个加载器，如果适用的话，尽管有些可能不需要真正的详细说明。让我们从 `cache-loader` 开始。

# cache-loader

缓存是我们在上一章中提到的内容。`cache-loader` 允许从加载器创建缓存。我们可以按照以下方式设置它：

1.  首先通过**命令行界面**（**CLI**）安装加载器，如下所示：

```js
npm install --save-dev cache-loader
```

请注意，我们的配置中执行了其他加载器（请参见以下代码），并且将由以 `cache-loader` 开头的任何加载器生成的任何输出进行缓存。默认情况下，这将在项目文件夹中进行，但也可以配置为在数据库中进行。

1.  要配置此内容，请使用 `webpack.config.js`：

```js
module.exports = {
 module: {
  rules: [
  {
    test: /\.ext$/,
    use: ['cache-loader', 'babel-loader'],
    include: path.resolve('src'),
   },
  ],
 },
};
```

请注意，`cache-loader` 放置在配置中的位置应该始终放在其他加载器之前。

这解释了安装和使用 `cache-loader`。我们将以相同的方式介绍其他几个加载器，从 `worker-loader` 开始。虽然它总是与其他加载器以链式或序列的方式使用，但由于它需要首先声明，因此我们应该首先讨论它。

# worker-loader

`worker-loader` 本质上为开发人员提供了一个解决方案，用于在后台处理大型计算任务。要使加载器运行起来，我们将采取以下步骤：

1.  首先，使用命令行安装 `worker-loader`：

```js
npm install worker-loader --save-dev
```

另外，还有一种内联方式从 `App.js` 文件导入 `worker-loader`。在任何 Webpack 项目目录中的这个文件中，如果还没有进行以下修改，可以进行以下修改：

```js
import Worker from 'worker-loader!./Worker.js';
```

1.  一旦导入了加载器，就使用 `webpack.config.js` 进行配置：

```js
{
 module: {
  rules: [
  {
   test: /\.worker\.js$/,
   use: { 
      loader: 'worker-loader' 
      }
    }
   ]
  }
 }
```

`use` 指的是允许访问加载器所需的配置。

1.  在 `App.js` 中编写以下代码，以允许该文件成为加载器的导出位置：

```js
import Worker from './file.worker.js';
const worker = new Worker();
worker.postMessage({ a: 1 });
worker.onmessage = function (event) {};
worker.addEventListener("message", function (event) {});
```

前面的代码还添加了一个`event`监听器，以便以后在开发控制台中进行测试。

1.  最后，通过您喜欢的方法运行 Webpack 以查看结果：

```js
npm run build
```

如果您选择了该方法，您应该看到`worker-loader`已安装并从`App.js`导入。这可以在控制台窗口中观察到，也可以通过查看页面源代码来观察到。

这为您提供了两种使用`worker-loader`的选择，可以通过命令行实用程序或通过`App.js`文件的配置。接下来，我们将讨论`coffee-loader`。

# coffee-loader

CoffeeScript 是 JavaScript 的简化形式，但它并不完全是 JavaScript，因此必须使用加载器才能在 Webpack 中使用它。

让我们按照以下步骤来使用`coffee-loader`：

1.  首先安装`coffee-loader`。要安装加载器，请使用以下命令行：

```js
npm install --save-dev coffee-loader
```

1.  确保您正在使用推荐的加载器配置进行测试，并使用`literate`键。为了进行测试，加载`coffee-loader`并将`literate`键设置为`true`。`literate`键将确保加载器的使用由编译器解释：

```js
module.exports = {
    module: {
      rules: [
       {
          test: /\.coffee.md$/,
          use: [{
          loader: 'coffee-loader',
          options: {
            literate: true
         }
      }]
    }]
  }
}
```

上述示例中的代码显示了如何使用加载器以及设置新规则。

1.  如果需要，我们将向您展示如何安装`coffee-redux`。**Redux**是用于管理 JavaScript 应用程序状态的开源库。它经常与**React**和**Angular**等库一起使用。要安装它，请键入以下命令：

```js
npm i -D coffee-redux-loader
```

上述示例不仅将帮助您了解在包中安装和使用 CoffeeScript 的过程，还将帮助您了解这里未提及的加载器的工作原理，因为它们的工作方式基本相同。

但是，您会看到，已经使用了快捷安装和开发模式来设置命令行—`i`和`-D`。在大多数情况下，这是有效的，尽管您可能会发现，在您的命令行实用程序与您使用的 Webpack 版本之间存在兼容性问题时，现在会有响应。

以这种方式做事可以节省您的时间，但是如果有疑问，请使用本指南中演示的冗长命令行约定。

现在，让我们转向`coverjs`，它的工作方式略有不同。

# coverjs

`coverjs`允许对您的代码进行仪器化。这基本上意味着它允许对您的代码进行性能测量或监视。

`coverjs`加载器不需要与`mocha-loader`结合使用，因为它是独立的。`reportHtml`函数将附加到输出的主体部分。

在以下示例中，`webpackOptions.js`是代码的主题。在第一组花括号（`{`）中是与模块导出程序相关的选项。在双花括号（`[{`）中是绑定`coverjs`加载器和`test:""`语句的代码（表示每个文件都将被测试）：

```js
webpack - dev - server "mocha!./cover-my-client-tests.js"--options webpackOptions.js
// webpackOptions.js
module.exports = {
    output: "bundle.js",
    publicPrefix: "/",
    debug: true,
    includeFilenames: true,
    watch: true,
    postLoaders: [{
       test: "",
       exclude: [
         "node_modules.chai",
         "node_modules.coverjs-loader",
         "node_modules.webpack.buildin"
    ],
    loader: "coverjs-loader"
 }]
}
// cover-my-client-tests.js
require("./my-client-tests");
after(function() {
   require("cover-loader").reportHtml();
});
```

正如您所看到的，这个特定的加载器通过本地文件设置了它的选项。对此的修改将产生与上一章讨论的配置相同的效果。这应该是您在应用程序中启动`coverjs`所需的全部内容。接下来是一个更复杂的主题，涉及使用国际语言。

# i18n-loader

`i18n-loader`处理国际化（`i18n`），这是准备应用程序以支持本地语言和文化设置的过程。让我们通过以下步骤进行设置：

1.  从命令行安装开始：

```js
npm install i18n-loader
```

1.  现在，让我们从使用 CSS 开始。我们将为`i18n`**设置我们的样式表。**这是通过我们通常的项目样式表`css/styles.css`完成的。如果您导入另一个样式表，也可以在那里进行修改：

```js
. / colors.json {
        "red": "red",
        "green": "green",
        "blue": "blue"
    }
    . / de - de.colors.json {
        "red": "rot",
        "green": "green"
    }
```

假设我们的区域设置是`de-de-berlin`（德语语言和区域设置，以此为例），现在可以调用加载器。

1.  接下来，我们将通过使用`index.js`文件为`i18n`设置本地化代码的颜色方案：

```js
var locale = require("i18n!./colors.json");
```

现在，等待状态准备就绪。这只需要一次，因为同一语言的所有区域设置都会合并成一个模块块：

```js
locale(function() {
 console.log(locale.red); // prints red
 console.log(locale.blue); // prints blue
});
```

通常这都是在与之前相同的文件中完成的。前面的代码将在`console.log`函数中的`locale`变量中添加一个子节点，这将有助于测试。

1.  现在，使用`webpack.config.js`配置加载器，并利用相关的可用选项。由于该加载器也有选项，如果你想要一次加载所有区域设置并且想要同步使用它们，你应该告诉加载器所有的区域设置：

```js
{
    "i18n": {
        "locales": [
            "de",
            "de-de",
            "fr"
        ],
        // "bundleTogether": false
    }
}
```

请注意前面代码中的`// "bundleTogether": false`语句，这可以取消注释并设置为禁用区域设置的捆绑。

还有其他的调用方式。以下代码通过区域设置选择正确的文件：

```js
require("i18n/choose!./file.js"); 
```

但是，这不会合并对象。在下面的代码中，第一行将连接所有符合条件的区域设置，第二行将合并生成的对象：

```js
require("i18n/concat!./file.js"); 
require("i18n/merge!./file.js"); 
```

因此，在前面的代码块中，编译时会执行`./file.js`：

```js
require("i18n!./file.json") ==
   require("i18n/merge!json!./file.json")
```

前面的代码块只是加强了正则表达式。它确保`require`语句中的任何一个都会加载相同的文件。

如果你想在 Node.js 中使用`require`，不要忘记进行 polyfill。请参阅本章末尾的*进一步阅读*部分，了解相关的 Webpack 文档。

前面的代码块只是调整了你的项目，使其与德语领土和德语听众兼容。接下来是`imports-loader`。

# imports-loader

`imports-loader`允许你使用依赖于特定全局变量的模块。这对于可能依赖于全局变量的第三方模块很有用。`imports-loader`可以添加必要的`require`调用，使它们能够与 Webpack 一起工作。让我们通过以下步骤进行设置：

1.  要在命令行中安装加载器，请使用以下语句：

```js
npm install imports-loader
```

假设你有`example.js`文件，这个加载器允许你使用 jQuery 将导入的脚本附加到图像标签中，如下所示：

```js
$("img").doSomeAwesomeJqueryPluginStuff();
```

1.  然后可以通过配置`imports-loader`将`$`变量注入到模块中，如下所示：

```js
require("imports-loader?$=jquery!./example.js");
```

这将简单地将`var $ = require("jquery");`添加到`example.js`的开头。例如，如果你正在优化代码以在本地运行库，这可能会很有用。

类似地，使用`polymer-loader`可以优化代码或自动化流程以允许转换。这是我们讨论的下一个主题。

# polymer-loader

`polymer-loader`用于将 HTML 文件转换为 JavaScript 文件。要配置加载器，请在`webpack.config.js`中使用以下代码：

```js
{
  test: /\.html$/,
  include: Condition(s) (optional),
  exclude: Condition(s) (optional),
  options: {
    ignoreLinks: Condition(s) (optional),
    ignorePathReWrite: Condition(s) (optional),
    processStyleLinks: Boolean (optional),
    htmlLoader: Object (optional)
  },
  loader: 'polymer-webpack-loader'
},
```

`polymer-webpack-loader`短语允许开发人员在单个文档中编写 HTML、CSS 和 JavaScript 代码作为聚合元素，例如，同时仍然能够使用完整的 Webpack 系统，包括模块捆绑和代码拆分。

# script-loader

`script-loader`基本上允许 JavaScript 在单个实例中加载。这适用于整个项目。让我们通过以下步骤进行设置：

1.  要安装`script-loader`，在命令行中输入以下内容：

```js
npm install --save-dev script-loader
```

请注意这在 Node.js 中不起作用。

1.  使用`webpack.config.js`配置 Webpack，将`exec`从`'script.exec.js';`导出：

```js
module.exports = {
    module: {
        rules: [{
            test: /\.exec\.js$/,
            use: ['script-loader']
        }]
    }
}
```

还有一种内联的方法，如下所示：

```js
import exec from 'script-loader!./script.js';
```

这应该是你在 Webpack 应用程序中使用`script-loader`所需要的全部内容。接下来是`source-map-loader`。

# source-map-loader

`source-map-loader`从项目中的所有 JavaScript 入口中提取现有的源映射。这包括内联源映射以及外部加载的源映射。所有源映射数据都按照你在`webpack.config.js`中使用`devtool`选项指定的源映射样式进行处理。以下代码显示了该配置：

```js
module.exports = {
     module: {
     rules: [
     {
       test: /\.script\.js$/,
       use: [
   {
     loader: 'script-loader',
     options: {
           sourceMap: true,
              },
   },
        ]
    }
         ]
    }
 }
```

当使用具有源映射的第三方库时，此加载器可能非常有用。如果不将其提取并处理为包的源映射，浏览器可能会错误地解释源映射数据。此加载器允许在库和框架之间维护源映射数据的连续性，以确保轻松调试。

该加载器将从任何 JavaScript 文件中提取，包括`node_modules`目录中的文件。在设置`include`和`exclude`规则条件时，应注意优化捆绑性能。

# less-loader

**`less-loader`**加载**LESS**（一种**CSS**类型）脚本。你应该以通常的方式使用命令行安装它，例如`npm i less-loader`。对于未经培训的人来说，LESS 是 CSS 的一种更简洁的语法形式，对于向后兼容性非常有用。

你应该将`less-loader`与`css-loader`和`style-loader`链接起来，以立即将所有样式应用到文档中。要配置此项，请使用以下示例代码，使用`webpack.config.js`文件：

```js
module.exports = {
    module: {
        rules: [{
            test: /\.less$/,
            use: [{
                    loader: 'style-loader', // creates style nodes 
                                               from JS strings

                },
                {
                    loader: 'css-loader', // translates CSS 
                                              into  CommonJS
                },
                {
                    loader: 'less-loader', // compiles Less to CSS
                },
            ],
        }, 
      ],
    },
 };
```

你可以通过加载器选项将任何 LESS 特定选项传递给`less-loader`。由于这些选项作为程序的一部分传递给 LESS，它们需要以`camelCase`形式传递；以下示例在**`webpack.config.js`**中展示了如何做到这一点：

```js
module.exports = {
    module: {
        rules: [{
            test: /\.less$/,
            use: [{
                    loader: 'style-loader',
                },
                {
                    loader: 'css-loader',
                },
                {
                    loader: 'less-loader',
                    options: {
                        strictMath: true,
                        noIeCompat: true,
                    },
                },
            ],
         },
       ],
    },
 };
```

请注意，LESS 不会将所有选项单独映射到`camelCase`。建议你检查相关的可执行文件，并搜索`dash-case`选项。

在生产模式下，通常建议使用`MiniCssExtractPlugin`将样式表提取到专用文件中。这样，你的样式就不会依赖于 JavaScript（稍后会详细介绍）。

在本节中，我们深入讨论了加载器，并对一些更有用的加载器进行了详细的检查。大多数加载器都遵循相同的安装和配置逻辑，并由 Webpack 社区构建，而不是由 Webpack 自己构建。我们将在本书的最后一章中更详细地讨论自定义加载器。

这里有太多其他加载器要提及，但这为你提供了一个非常坚实的基础，可以以各种富有想象力的方式与它们一起工作。与加载器通常处理的非本地脚本相关的东西是使用 Webpack 的 API。我们将在下一节中进行调查。

# API

API 对于充分利用 Webpack 至关重要。简单来说，API 在应用程序和网站之间进行通信时是必需的。对于像 Webpack 这样的 JavaScript 捆绑器，这包括数据库和后端连接。

在使用 JavaScript 时，有大量的 API 可用，但我们无法在这里逐一介绍它们；然而，有一些更有用的常见但也复杂的 API 在使用 Webpack 进行编程时经常被用作工具。

这些工具是特定于 Webpack 的，允许在 Webpack 中进行广泛或多功能的功能，而不仅仅是简单地访问外部代码。其中最值得注意的工具是 Babel 和 Node.js。因此，让我们以这些工具为例，并在接下来的小节中学习它们的用法，首先是 Babel。

# Babel 及其加载器构建者

如果你不知道，Babel 是一个主要将 ECMAScript 2015 及其前版本代码转换为与当前和旧版浏览器或环境兼容的 JavaScript 的工具链。Babel 可以为开发者做的主要事情如下：

+   转换语法

+   使用`@babel/polyfill`填充目标环境中缺失的功能

+   执行源代码转换，称为代码修改

Webpack 使用 Babel 接口的 API。如果你尝试使用命令行安装它，你应该会收到以下消息：

```js
The Node.js API for babel has been moved to babel-core.
```

如果收到此消息，意味着你已经安装了`Babel`并且在 Webpack 配置文件中使用了加载器的简短表示法（这在 Webpack 2 及更高版本中已不再有效）。

在`webpack.config.js`中，您可能会看到以下脚本：

```js
  {
    test: /\.m?js$/,
    loader: 'babel',
  }
```

由于安装了 Babel，Webpack 尝试加载`babel`包而不是`babel-loader`。

为了解决这个问题，应该安装`npm`包 Babel，因为它在 Babel 版本 6 中已被弃用。如果您使用的是 Babel 版本 6，则应该安装`@babel/cli`或`@babel/core`。如果您的一个依赖项正在安装 Babel，并且您无法自行卸载它，请在`webpack.config.js`中使用加载器的完整名称：

```js
  {
    test: /\.m?js$/,
    loader: 'babel-loader',
  }

```

到目前为止，您所遵循的示例应该为您在一般情况下使用 Babel 奠定了良好的基础，但 Babel 的一个关键用途是自定义加载器。这是本书最后一章更全面地介绍的一个主题，但我们现在将讨论 Babel 如何与自定义加载器一起工作，特别是因为您可能不使用自定义的加载器。

`babel-loader`公开了一个`loader-builder`实用程序，允许用户为它处理的每个文件添加 Babel 配置的自定义处理。

`.custom`短语接受一个回调函数，将使用 Babel 的加载器实例进行调用。这样工具可以确保它使用与加载器本身相同的`@babel/core`实例。

在您想要自定义但实际上没有文件调用`.custom`的情况下，您还可以使用`customize`选项，并将其指向导出您自定义回调函数的文件的字符串。

可能了解其工作原理的最佳方法是通过一个实际的例子；让我们在以下练习中进行一次。

这个例子的目标是演示如何使用`babel-loader`来构建自定义加载器。

这个例子首先使用了一个自定义的文件名。这可以是任何你想要的，但为了这个练习，我们选择的名称是`./my-custom-loader.js`。您可以从这个位置或任何您想要的地方导出：

1.  首先，通过使用以下代码在`./my-custom-loader.js`中创建一个自定义文件：

```js
module.exports = require("babel-loader").custom(babel => {
 function myPlugin() {
 return {
 visitor: {},
 };
 }
```

在上面的代码块中，我们可以看到一个`require`语句。这使用了`babel-loader`，我们需要创建自定义加载器。

1.  现在，我们需要配置我们的项目以设置传递给加载器的传递，如下所示：

```js
return {
    customOptions({
        opt1,
        opt2,
        ...loader
    }) {
        return {
            custom: {
                opt1,
                opt2
            },
            loader,
        };
    },
```

请注意，`custom:`指的是提取加载器可能具有的任何自定义选项。还要注意两个选项后面的`loader`引用。这将删除两个`custom`选项并将选项传回。

1.  然后，我们传递 Babel 的`PartialConfig`对象，将正常配置设置为`return cfg.options`：

```js
config(cfg) {
    if (cfg.hasFilesystemConfig()) {
        return cfg.options;
    }

    return {
        ...cfg.options,
        plugins: [
            ...(cfg.options.plugins || []),
            testPlugin,
        ],
    };
},
```

在上述代码中，当`testPlugin`语句被执行时，我们可以看到自定义插件的包含，然后将作为一个选项可用。

1.  现在，让我们创建占位文本来测试自定义加载器。前面的代码应该生成类似以下的内容：

```js
result(result) {
return {
    ...result,
    code: result.code + "\n// Generated by this custom loader",
    };
    },
    };
});
```

这个代码块显示了自定义加载器正在生成代码。

1.  确保您的配置是正确的。请注意，您应该始终将`__dirname`和`custom-loader`替换为您选择的名称。在 Webpack 配置模块中，键入以下内容：

```js
.exports = {
    module: {
        rules: [{
            loader: path.join(__dirname, 'custom-loader.js'),
        }]
    }
};
customOptions(options: Object): {
    custom: Object,
    loader: Object
}

```

上面的代码块向您展示了如何设置和配置`customOptions`。

1.  根据加载器的选项，将自定义选项从`babel-loader`的选项中拆分出来：

```js
config(cfg: PartialConfig): Object
```

1.  给定 Babel 的`PartialConfig`对象，返回应传递给`babel.transform`的`options`对象：

```js
result(result: Result): Result
```

前面两个代码块都涉及到我们构建的自定义文件的内容，在这个例子中是`./my-custom-loader.js`。

请注意，Babel 的`result`对象将允许加载器对其进行额外的调整。

这应该是你需要让自定义加载器与 Babel 一起工作的全部内容。阅读本书最后一章有关编写和自定义加载器的更多信息。在 Webpack 项目中经常使用的另一个关键 API 是 Node.js API。

# Node.js API

当使用自定义开发流程时，Node.js API 非常有用。这是因为所有的报告和错误处理都是手动完成的。在这种情况下，Webpack 只是处理编译过程。请注意，在使用 Node.js API 时，`stats`配置选项将不会产生任何效果。

当您安装 Webpack 5 时，这个 API 将被安装；如果您按顺序阅读本节，可以参考第一章。让我们通过以下步骤设置这个 API：

1.  首先，将`webpack`模块包含到您的 Node.js 脚本中。这是通过`webpack.config.js`文件完成的：

```js
const webpack = require('webpack');

webpack({
  // Configuration Object
}, (some, stats) => { // Stats Object
  if (some || stats.hasErrors()) {
    // Handle errors here
  }
  // Done processing
});
```

在上面的例子中，提供了一个回调函数`webpack()`，它运行编译器。代码呈现了一些条件。这只是一个例子，当然应该用您的代码替换。同样，`some`术语应该被替换为与您的项目相关的正确对象名称。

请注意，`some`对象不会包括编译错误，而只包括与 Webpack 特定的问题，如错误配置相关的问题。这些错误将使用`stats.hasErrors()`函数来处理。

1.  接下来，确保正确传递编译器实例。

如果 Webpack 函数没有提供回调，它将返回一个`compiler`实例。`compiler`实例可以手动触发`webpack()`函数，或者确保它在构建过程中观察更改（使用`.run(callback)`或`.watch(watchOptions, handler)`），甚至在不需要 CLI 的情况下运行构建本身。

`compiler`实例允许使用子编译器，并将所有捆绑、写入和加载工作委托给注册的插件。

有一个叫做`hook`属性，它是`compiler`实例的一部分。它的目的是在编译器的生命周期中注册任何插件到任何钩子事件。您可以使用`WebpackOptionsDefaulter`和`WebpackOptions Apply`工具来配置这个编译器。

在构建运行完成后，之前提到的回调函数将被执行。使用这个函数来最终记录任何错误或统计信息。

Node.js API 只支持单个编译一次。并发的观察或构建可能会破坏输出捆绑包。

使用 API 调用运行类似于使用`compiler`实例。

1.  现在我们应该使用`webpack.config.js`运行一个编译：

```js
const webpack = require('webpack');

const compiler = webpack({
 // Configuration Object
});

compiler.run((some, stats) => { // Stats Object
});
```

1.  从这里，我们还可以触发一个`watch`会话。当`webpack()`函数检测到更改时，它将再次运行并返回一个`watching`实例：

```js
watch(watchOptions, callback);
const webpack = require('webpack');

const compiler = webpack({
 // Configuration Object
});

const watching = compiler.watch({
 // Example watchOptions
 aggregateTimeout: 300,
 poll: undefined
}, (some, stats) => { // Stats Object
 // Print watch/build result here...
 console.log(stats);
});
```

由于文件系统的不准确性可能会触发多次构建，如果检测到更改，前面代码块中的`console.log`语句可能会多次触发任何单个修改。检查`stats.hash`可以帮助您查看文件是否已更改。

1.  使用这种方式的`watch`方法将返回一个`watching`实例和一个`.close(callback)`方法。调用这个方法将结束`watching`会话：

```js
watching.close(() => {
 console.log('Watching Ended.');
});
```

请注意，使用`invalidate`观察函数将允许手动使当前编译无效，而不会停止`watch`过程。这很有用，因为一次只允许运行一次：

```js
watching.invalidate();
```

由于多个同时的编译是受限制的，Webpack 提供了一个叫做`MultiCompiler`的东西来加快项目的开发。它是一个模块，允许 Webpack 在单独的编译器中运行多个配置。如果您的`options`参数是一个数组，Webpack 将应用单独的编译器，并在所有编译器完成其过程后执行任何回调：

```js
var webpack = require('webpack');
webpack([
 { entry: './index1.js', output: { filename: 'bundle1.js' } },
 { entry: './index2.js', output: { filename: 'bundle2.js' } }
], (some, stats) => { // Stats Object
 process.stdout.write(stats.toString() + '\n');
})
```

上面的代码块向您展示了如何在`webpack.config.js`中配置项目以允许这个过程。

正如所解释的，尝试并行运行这些编译将产生不正确的输出。如果这是意外发生的，错误管理就变得很重要。

一般来说，错误处理包括三种类型的错误——严重的 Webpack 错误（例如配置错误）、编译错误（例如缺少资源）和编译警告。

以下代码块向您展示了如何配置您的项目——在本例中，使用 `webpack.config.js`——来处理这些错误：

```js
const webpack = require('webpack');

webpack({
 // Configuration Object
}, (some, stats) => {
 if (some) {
   console.error(some.stack || some);
 if (some.details) {
   console.error(some.details);
 }
 return;
 }
const info = stats.toJson();
if (stats.hasErrors()) {
  console.error(info.errors);
 }
if (stats.hasWarnings()) {
  console.warn(info.warnings);
 }
// Log results...
});
```

在上述代码块中，`some` 元素表示这些错误作为一个变量。我们可以看到各种条件将在控制台日志中注册这些错误。

我们已经为您提供了关于如何使用 Webpack 的 API 的密集速成课程，所以如果您幸存下来，现在您是编程技能的专家。干得好！

现在我们已经探讨了各种加载器和 API（包括 Babel 和 Node.js），是时候看一下本章涵盖的最后一个功能了——插件。

# 插件

插件的作用是做任何加载器无法做到的事情。加载器通常帮助运行不适用于 Webpack 的代码，插件也是如此；然而，加载器通常由社区构建，而插件由 Webpack 的内部开发人员构建。

插件被认为是 Webpack 的支柱。该软件是建立在与您在 Webpack 配置中使用的相同的插件系统上的。

Webpack 有丰富的插件接口，Webpack 自身的大多数功能都使用它。以下是本节将详细介绍的可用插件的项目列表。每个名称旁边都有一个插件的简要描述：

+   `BabelMinifyWebpackPlugin`：使用 `babel-minify` 进行最小化

+   `CommonsChunkPlugin`：提取在块之间共享的公共模块

+   `ContextReplacementPlugin`：覆盖 require 表达式的推断上下文

+   `HotModuleReplacementPlugin`：启用 **热模块替换**（**HMR**）（稍后详细介绍）

+   `HtmlWebpackPlugin`：轻松创建用于提供捆绑包的 HTML 文件

+   `LimitChunkCountPlugin`：设置分块的最小/最大限制，以更好地控制该过程

+   `ProgressPlugin`：报告编译进度

+   `ProvidePlugin`：使用模块而无需使用 `import`/`require`

+   `TerserPlugin`：启用对项目中 Terser 版本的控制

Webpack 社区页面上有许多其他插件可用；然而，上述列表说明了更显著和有用的插件。接下来，我们将详细解释每一个。

我们不会详细介绍最后三个插件，因为它们只需要按照通常的方式安装。

每个插件的安装都遵循与加载器相同的过程：

1.  首先，使用命令行安装插件，然后修改配置文件以引入插件，类似于以下示例：

```js
npm install full-name-of-plugin-goes-here-and-should-be-hyphenated-and-not-camelcase --save-dev
```

请记住，这只是一个通用示例；您将需要添加您的插件名称。与之前使用的相同的 Webpack 项目和相同的配置文件 `webpack.config.js` 一样，以下配置也是如此。

1.  现在我们应该准备我们的配置文件：

```js
const MinifyPlugin = require("full-name-of-plugin-goes-here-and-should-be-hyphenated-not-camelcase");
module.exports = {
 entry: //...,
 output: //...,
 plugins: [
 new MinifyPlugin(minifyOpts, pluginOpts)
 ]
}
```

这就结束了关于插件的一般介绍。我们采取了一般方法来防止过度复杂化。现在，我们可以继续讨论 Webpack 上可用的各种插件的一些有趣方面。在下一小节中，我们将讨论以下内容：

+   `BabelMinifyWebpackPlugin`

+   `CommonsChunkPlugin`

+   `ContextReplacementPlugin`

+   `HtmlWebpackPlugin`

+   `LimitChunkCountPlugin`

大多数插件由 Webpack 内部开发，并填补了加载器尚不能填补的开发空白。以下是一些更有趣的插件。让我们从 `BabelMinifyWebpackPlugin` 开始。

# BabelMinifyWebpackPlugin

在本小节中，我们将安装 `BabelMinifyWebpackPlugin`。该插件旨在最小化 Babel 脚本。如前所述，最小化是指删除错误或多余的代码以压缩应用程序大小。要使用 `babel-loader` 并将 `minify` 作为预设包含在内，使用 `babel-minify`。使用此插件的 `babel-loader` 将更快，并且将在较小的文件大小上运行。

Webpack 中的加载器操作单个文件，`minify`的预设将直接在浏览器的全局范围内执行每个文件；这是默认行为。顶层范围中的一些内容将不被优化。可以使用以下代码和`minifyOptions`来优化文件的`topLevel`范围：

```js
mangle: {
topLevel: true
}
```

当`node_modles`被排除在`babel-loader`的运行之外时，排除的文件不会应用缩小优化，因为没有传递给`minifer`。

使用`babel-loader`时，生成的代码不经过加载器，也不被优化。

插件可以操作整个块或捆绑输出，并且可以优化整个捆绑包，可以在缩小的输出中看到一些差异；但是，在这种情况下，文件大小将会很大。

Babel 插件在使用 Webpack 时非常有用，并且可以跨多个平台使用。我们将讨论的下一个插件是`CommonsChunkPlugin`，它旨在与多个模块块一起使用，这是 Webpack 非常本地的功能。

# CommonsChunkPlugin

`CommonsChunkPlugin`是一个可选功能，它创建一个称为块的单独功能。块由多个入口点之间共享的公共模块组成。

这个插件已经在 Webpack 4（Legato）中被移除了。

查看`SplitChunkPlugin`将更多地了解 Legato 中如何处理块。

生成的分块文件可以通过分离形成捆绑包的公共模块来最初加载一次。这将被存储在缓存中以供以后使用。

以这种方式使用缓存将允许浏览器更快地加载页面，而不是强制它加载更大的捆绑包。

在您的配置中使用以下声明来使用这个插件：

```js
new webpack.optimize.CommonsChunkPlugin(options);
```

一个简短而简单的安装，但是值得介绍。接下来，让我们使用`ContextReplacementPlugin`。

# ContextReplacementPlugin

`ContextReplacementPlugin`是指带有扩展名的`require`语句，例如以下内容：

```js
require('./locale/' + name + '.json')
```

当遇到这样的表达式时，插件将推断`./local/`的目录和一个正则表达式。如果在编译时没有包含名称，那么每个文件都将作为模块包含在捆绑包中。这个插件将允许覆盖推断的信息。

下一个要讨论的插件是`HtmlWebpackPlugin`。

# HtmlWebpackPlugin

`HtmlWebpackPlugin`简化了创建用于提供捆绑包的 HTML 文件。这对于包含文件名中的哈希值的捆绑包特别有用，因为每次编译都会更改。

使用这种方法时，我们有三种选择——使用带有`lodash`模板的模板，使用您的加载器，或者让插件生成一个 HTML 文件。模板只是一个 HTML 模板，您可以使用`lodash`自动加载以提高速度。加载器或插件可以生成自己的 HTML 文件。这都可以加快任何自动化流程。

当使用多个入口点时，它们将与生成的 HTML 中的`<script>`标签一起包含。

如果 Webpack 的输出中有任何 CSS 资产，那么这些资产将包含在生成的 HTML 的`<head>`元素中的`<link>`标签中。例如，如果使用`MiniCssExtractPlugin`提取 CSS。

回到处理块。下一个要看的插件是处理限制块计数的插件。

# LimitChunkCountPlugin

在按需加载时使用`LimitChunkCountPlugin`。在编译时，您可能会注意到一些块非常小，这会产生更大的 HTTP 开销。`LimitChunkCountPlugin`可以通过合并块来后处理块。

通过使用大于或等于`1`的值来限制最大块数。使用`1`可以防止将额外的块添加为主块或入口点块：

```js
[/plugins/min-chunk-size-plugin]
```

保持块大小在指定限制以上不是 Webpack 5 中的一个功能；在这种情况下应该使用`MinChuckSizePlugin`。

这就结束了我们对插件的介绍以及本章的总结。插件使 Webpack 能够以各种方式工作，而 Webpack 使开发人员能够构建加载程序并填补功能问题的空白。在处理大型项目或需要自动化的复杂项目时，它们是不可或缺的。

我们关于 API 的部分向您展示了，有时我们并不总是想使用本地代码，并为您提供了一个很好的过渡到我们将在下一章中讨论的库。

# 摘要

本章深入介绍了加载程序及其在 Webpack 中的使用方式。加载程序对于 Webpack 来说是基础，但插件是核心和支柱。本章带您了解了这些主题的主要特点，展示了每个主题的最佳用法以及何时切换使用它们的好时机。

然后我们探讨了插件及其使用方式，包括 Babel、自定义插件和加载程序。我们还研究了 API 及其使用方式，特别是那些在 Webpack 中实现更广泛功能的 API，比如 Babel 和 Node API。

在下一章中，我们将讨论库和框架。我们对插件、API 和加载程序的研究表明，有时我们不想使用诸如库之类的远程代码，但有时我们确实需要。Webpack 通常处理本地托管的代码，但有时我们可能需要使用库。这为我们提供了一个很好的过渡到这个主题。

# 问题

1.  什么是`i18n`加载程序？

1.  Webpack 通常使用哪种工具链来转换 ECMA 脚本？

1.  Babel 主要用于什么？

1.  哪个加载程序允许用户添加对 Babel 配置的自定义处理？

1.  `polymer-webpack-loader`是做什么的？

1.  `polymer-webpack-loader`为开发人员提供了什么？

1.  在使用 Node.js API 时，提供的回调函数将运行什么？


# 第五章：库和框架

本章将探讨应用程序如何与库和框架一起工作。许多框架和库与 Webpack 一起工作。通常，这些是 JavaScript 框架。它们正变得越来越成为编程的核心部分，了解如何将它们集成到应用程序捆绑包中可能会成为一个日益增长的需求。

与其他 Webpack 元素的工作有些不同，使用库和框架。通过典型的例子和用例，本书将探讨 Angular 以及如何构建 Angular 框架以便进行包捆绑。这包括对 Webpack 捆绑的期望，期望的结果，优势和局限性。

完成本章后，您应该能够自信地使用这些主要框架和库与 Webpack 一起使用。您还将知道如何集成和安装它们，以及如何在集成中使用最佳实践。

在本章中，我们将涵盖以下主题：

+   最佳实践

+   使用 JSON

+   使用 YAML

+   使用 Angular

+   使用 Vue.js

# 最佳实践

到目前为止，我们只涵盖了构建 Vanilla JavaScript，这不应与 Vanilla 框架混淆。尽管这是学习的最佳方式，但更有可能的是您将使用某种框架。Webpack 将与任何 JavaScript 或 TypeScript 框架一起工作，包括 Ionic 和 jQuery；然而，更棘手的框架包括 Angular、Vue 和 YAML。

现在，我们将开始使用 YAML，但在深入研究之前，您可能想知道是否可以集成后端框架。简单的答案是可以，但它们不会被捆绑。然而，唯一的集成级别是通过链接源代码，就像我们在大多数项目或 API 中所做的那样，比如 REST API。

正如我们已经讨论过的，Webpack 有生产模式和开发模式。生产模式将您的项目捆绑成最终状态，准备好进行网络交付或发布，并且提供了很少的调整空间。开发模式给开发人员自由修改数据库连接的权限；这是后端集成的方式。您的项目的后端可能是**ASP.NET**或**PHP**，但有些后端更复杂，使用`OpenAuth`。作为开发人员，您需要对所有这些有一个概览。然而，本指南只涉及 Webpack。

请放心，所有这些框架都将集成，这是通过 REST API 完成的，它以**JavaScript 对象表示**（**JSON**）格式返回数据。也可以使用**AJAX**来完成这一点。无论如何，请确保遵循安全的最佳实践，因为与使用服务器端脚本相比，对数据库的 JSON 调用并不安全。

如果您的项目使用 Ionic，那么您应该按照 Angular 的说明进行操作，因为 Ionic 框架是基于此的。

这应该为您提供了与后端和库一起工作的最佳实践的全面概述。现在我们将讨论您在 Webpack 中会遇到的每个常见库。让我们从 JSON 开始，因为它是最容易理解的，也是外部或后端代码和数据库与您的 Webpack 应用程序交互的最重要方式。

# 使用 JSON

当您使用框架时，大部分时间您需要在不同语言和应用程序之间进行通信。这是通过 JSON 完成的。JSON 在这方面与 YAML 类似，但更容易理解 Webpack 如何与 JSON 一起工作。

JSON 文件可以被 Webpack 的编译器理解，无需专用加载程序，因此可以被视为 Webpack 捆绑器的本地脚本，就像 JavaScript 一样。

到目前为止，本指南已经提到，JSON 文件在包组合中起着重要作用。Webpack 记录和跟踪加载器和依赖项的使用是通过 JSON 文件的模式进行的。这通常是`package.json`文件，有时是`package.lock.json`文件，它记录了每个安装包的确切版本，以便可以重新安装。在这种情况下，“包”是指加载器和依赖项的集合。

每个 JSON 文件必须正确编程，否则 Webpack 将无法读取。与 JavaScript 不同，代码中不允许使用注释来指导用户，因此您可能希望使用`README`文件向用户解释其内容和目的。

JSON 文件的结构与 JavaScipt 有所不同，并包含不同的元素数组，例如键。以以下代码块为例：

```js
module: {
    rules: [{
    test: /\.yaml$/,
    use: 'js-yaml-loader',
    }]
}
```

这是`package.json`文件的一部分，我们稍后在本章中将使用。此块的内容基本上声明了模块的参数。命名模块用作键，并在其后加上冒号。这些键有时被称为名称，它们是选项的放置位置。此代码设置了一系列规则，在这个规则中是指示 Webpack 在转译内容模块时使用`js-yaml-loader`。

您必须确保大括号和方括号的使用顺序正确，否则 Webpack 将无法读取代码。

作为 JavaScript 开发人员，您可能对 JSON 及其用法非常熟悉。但是，为了排除任何盲点，值得详细说明。YAML 是一个更复杂的框架，但您经常会遇到它，因此它只比 JSON 逐渐更复杂。现在让我们开始逐步了解它。

# 使用 YAML

YAML 是一种常见的框架，类似于 JSON 的使用方式。不同之处在于 YAML 更常用于配置文件，这就是为什么在使用 Webpack 时您可能会更频繁地或者第一次遇到它。

要在 Webpack 中使用 YAML，我们必须安装它。让我们开始吧：

1.  您可以在命令行实用程序中使用`npm`安装 YAML。使用以下命令：

```js
yarn add js-yaml-loader
```

请注意`yarn`语句。这是指 JavaScript 文件的开源包管理器，预装在`Node.js`中。它的工作方式类似于`npm`，应该是预安装的。如果您在此处使用的代码没有得到响应，请再次检查是否已预安装。

1.  要从命令行界面检查 YAML 文件，您应该全局安装它们：

```js
npm install -g js-yaml

```

1.  接下来，打开配置文件`webpack.config.js`，并进行以下修改：

```js
import doc from 'js-yaml-loader!./file.yml';
```

前一行将返回一个 JavaScript 对象。这种方法适用于不受信任的数据。请参阅*进一步阅读*部分，了解 GitHub YAML 示例。

1.  之后，使用`webpack.config.js`配置文件来允许使用 YAML 加载器：

```js
module: {
    rules: [{
    test: /\.yaml$/,
    use: 'js-yaml-loader',
    }]
}
```

您可能还想为 Webpack 使用 YAML front-matter 加载器。这是一个 MIT 许可的软件，它将 YAML 文件转换为 JSON，如果您更习惯于使用后者，这将特别有用。如果您是 JavaScript 开发人员，您很可能习惯使用 JSON，因为它往往比 YAML 更常用于 JavaScript。

此模块需要在您的设备上安装 Node v6.9.0 和 Webpack v4.0.0 的最低版本。Webpack 5 是本指南的主题，所以不应该有问题。但是，请注意，此功能仅适用于 Webpack 4 和 5。

以下步骤与前面的步骤分开，因为它们涉及安装`yaml-loader`而不是`yaml-frontmatter`，后者用于将 YAML 转换为 JSON 文件（这更符合 Webpack 包结构的典型情况）：

1.  首先，您需要使用命令行实用程序安装`yaml-frontmatter-loader`：

```js
npm install yaml-frontmatter-loader --save-dev
```

这个特定的命令行可能在语法上与本指南过去展示的命令行不同，但无论格式如何，这个命令都应该有效。

1.  然后，按照以下方式向配置中添加加载器：

```js
const json = require('yaml-frontmatter-loader!./file.md');
```

此代码将`file.md`文件作为 JavaScript 对象返回。

1.  接下来，再次打开`webpack.config.js`，并对`rules`键进行以下更改，确保引用 YAML 加载器：

```js
module.exports = {
  module: {
    rules: [
      {
         test: /\.md$/,
         use: [ 'json-loader', 'yaml-frontmatter-loader' ]
      }
    ]
  }
}
```

1.  接下来，通过你喜欢的方法运行 Webpack 5，并查看结果！

如果你一口气通过了这一点，你可能已经足够勇敢去应对 Angular 了。这是一个更难处理的框架，所以让我们开始吧。

# 使用 Angular

Angular 是一个库和框架，与所有框架一样，它旨在使构建应用程序更容易。Angular 利用依赖注入、集成最佳实践和端到端工具，所有这些都可以帮助解决开发中的挑战。

Angular 项目通常使用 Webpack。在撰写本文时，使用的最新版本是**Angular 9**。每年都会推出更新版本。

现在，让我们看看 Webpack 在捆绑 Angular 项目或将 Angular 添加到现有项目时的工作原理。

Angular 寻找`window.jQuery`来确定是否存在 jQuery。查看以下源代码的代码块：

```js
new webpack.ProvidePlugin({
  'window.jQuery': 'jquery'
});
```

要添加`lodash`映射，请将现有代码附加到以下内容：

```js
new webpack.ProvidePlugin({
  _map: ['lodash', 'map']
});
```

Webpack 和 Angular 通过提供入口文件并让它包含从这些入口点导出的依赖项来工作。以下示例中的入口点文件是应用程序的根文件`src/main.ts`。让我们来看看：

1.  我们需要在这里使用`webpack.config.js`文件。请注意，这是一个单入口点过程：

```js
entry: {
 'app': './src/main.ts'
},
```

Webpack 现在将解析文件，检查它，并递归地遍历其导入的依赖项。

1.  在`src/main.ts`中进行以下更改：

```js
import { Component } from '@angular/core';
@Component({
 selector: 'sample-app',
 templateUrl: './app.component.html',
 styleUrls: ['./app.component.css']
})
export class AppComponent { }
```

Webpack 将识别出正在导入`@angular/core`文件，因此这将被添加到捆绑包含的依赖项列表中。Webpack 将打开`@angualar/core`文件，并跟踪其一系列`import`语句，直到从中构建出一个依赖图。这将从`main.ts`（一个 TypeScript 文件）构建出来。

1.  然后，将这些文件作为输出提供给在配置中标识的`app.js`捆绑文件：

```js
output: {
 filename: 'app.js'
}
```

包含源代码和依赖项的 JavaScript 文件是一个文件，输出捆绑文件是`app.js`文件。稍后将在`index.html`文件中使用 JavaScript 标签(`<script>`)加载它。

建议不要为所有内容创建一个巨大的捆绑文件，这是显而易见的。因此，建议将易变的应用程序代码与更稳定的供应商代码模块分开。

1.  通过更改配置，将应用程序和供应商代码分开，现在使用两个入口点——`main.ts`和`vendor.ts`，如下所示：

```js
entry: {
 app: 'src/app.ts',
 vendor: 'src/vendor.ts'
},
output: {
 filename: '[name].js'
}
```

通过构建两个单独的依赖图，Webpack 会发出两个捆绑文件。第一个称为`app.js`，而第二个称为`vendor.js`。分别包含应用程序代码和供应商依赖项。

在上面的示例中，`file name: [name]`表示一个占位符，Webpack 插件 app 和 vendor 将其替换为入口名称。插件将在下一章节中详细介绍，所以如果你遇到困难，也许可以标记这一页，然后再回来看看。

1.  现在，通过添加一个仅导入第三方模块的`vendor.ts`文件，指示 Webpack 哪些部分属于供应商捆绑，如下所示：

```js
import '@angular/platform-browser';
import '@angular/platform-browser-dynamic';
import '@angular/core';
import '@angular/common';
import '@angular/http';
import '@angular/router';
// RxJS
import 'rxjs';
```

请注意提到`rxjs`。这是一个用于响应式编程的库，旨在使开发人员更容易地组合异步代码或回调。

其他供应商也可以以这种方式导入，例如 jQuery、Lodash 和 Bootstrap。还可以导入的文件扩展名包括 **JavaScript** 文件（`.js`）、**TypeScript** 文件（`.ts`）、**层叠样式表** 文件（`.css`）和 **Syntactically Awesome Style Sheets** 文件（`.sass`）。

Angular 可能是一个非常复杂的框架，并且与基于 Web 的应用程序非常相关。然而，您的特定需求可能更适合单页应用程序，这种情况下，Vue.js 将是大多数人首选的选择。现在让我们来看一下它。

# 使用 Vue.js

Vue.js 是另一个框架，但是它是开源的。它的使用显著性，或者说明显的目的领域，是**单页应用**（**SPAs**）。这是因为该框架专注于提供无缝的体验，但功能比 Angular 少，可以与许多其他语言一起工作，并且运行速度非常快。使用 Vue.js 构建相当大的应用程序会导致在使用过程中加载非常缓慢，甚至编译速度更慢。

也许理解这一点的最好方法是考虑 jQuery 如何使用内联语句调用页面中的脚本，而 Angular 使用核心模块，每个模块都设计有特定的目的。Vue.js 介于纯粹简单的 jQuery 和 Angular 之间。

使用 Webpack 与 Vue.js 项目是通过使用专用加载器来完成的。

建议安装 `vue-loader` 和 `vue-template-compiler`，除非您是 Vue.js 模板编译器的高级用户。按照以下步骤进行：

1.  要按照这个示例进行，首先安装 `vue-loader` 和 `vue-template-compiler`，使用以下代码：

```js
npm install -D *vue-loader vue-template-compiler*
```

模板编译器必须单独安装，以便可以指定版本。

Vue.js 每次发布新版本都会发布相应版本的模板编译器。这两个版本必须同步，以便加载器生成的代码是运行时兼容的。因此，每次升级一个版本时，应该升级另一个版本。

与 Vue.js 相关的加载器与大多数加载器的配置略有不同。在处理扩展名为 `.vue` 的文件时，确保将 Vue.js 加载器的插件添加到您的 Webpack 配置中。

1.  这是通过修改 Webpack 的配置来完成的，下面的示例使用 `webpack.config.js`：

```js
const VueLoaderPlugin = require('vue-loader/lib/plugin')
module.exports = {
 module: {
 rules: [
 // other rules
 {
   test: /\.vue$/,
   loader: 'vue-loader'
  }
 ]
},
 plugins: [
 // make sure to include the plugin.
 new VueLoaderPlugin()
 ]
}
```

这个插件是必需的，因为它负责克隆已定义的文件，并将它们应用于与 `.vue` 文件对应的语言块。

1.  使用 Vue.js，我们添加以下内容：

```js
new webpack.ProvidePlugin({ Vue: ['vue/dist/vue.esm.js', 'default'] });

```

先前的代码必须添加，因为它包含了 ECMAScript 模块的完整安装，用于与打包工具一起使用 Vue.js。这应该存在于项目的 `npm` 包的 `/dist` 文件夹中。注意 `.ems.` 表示 ECMAScript 模块。Vue.js 安装页面上显示了运行时和生产特定的安装方法，这些方法可以在本章的 *进一步阅读* 部分找到。**UMD** 和 **CommonJS** 的安装方法类似，分别使用 `vue.js` 和 `vue.common.js` 文件。

由于我们的项目将使用 `.esm` 格式，了解更多关于它可能会很有用。它被设计为静态分析，这允许打包工具执行**摇树**，即消除未使用的代码。请注意，打包工具的默认文件是 `pkg.module`，它负责运行时 ECMAScript 模块编译。有关更多信息，请参阅 Vue.js 安装页面——URL 可在本章的 *进一步阅读* 部分找到。

这就结束了关于框架和库的内容。现在，您应该已经具备了处理复杂项目的强大能力，甚至可能会使用多个框架。

# 总结

本章涵盖了典型的框架以及如何开始使用它们。这包括应该遵循的安装过程以及需要的标准和外围设备。本指南关注最佳实践和安全性。在开始项目时，您应该提前遵循这些示例，密切关注程序、警告和要求。

本指南为您概述了其他框架，如用于回调的 RxJS 和 jQuery，以及在使用不寻常的文件扩展名时指引您正确方向。我们还探讨了在使用 Webpack 5 时 Angular 的核心功能和 Vue.js 的用法和安装程序，以及 Vue.js 如何更适合单页面应用程序，而 Angular 在更大的项目上的工作效果更好。

在涵盖了大部分核心主题之后，下一章我们将深入探讨部署和安装。在处理数据库并确保满足安全要求时，这将变得更加重要。下一章将对这个主题进行深入探讨，并希望能解决您作为开发人员可能遇到的任何问题。

# 进一步阅读

+   GitHub 的 YAML 示例：[`github.com/nodeca/js-yaml`](https://github.com/nodeca/js-yaml)

+   window.jQuery 源代码：[`github.com/angular/angular.js/blob/v1.5.9/src/Angular.js#L1821-L1823`](https://github.com/angular/angular.js/blob/v1.5.9/src/Angular.js#L1821-L1823.)

+   Vue.js 安装指南：[`vuejs.org/v2/guide/installation.html`](https://vuejs.org/v2/guide/installation.html)

# 问题

1.  与正在使用的`Vue.js`版本对应的编译器是什么？

1.  在使用 Angular 时，本指南建议将易变代码和稳定供应商代码分开。这是通过使用两个入口点来实现的。它们是什么？

1.  在使用 Webpack 时，使用 YAML 的最低安装要求是什么？

1.  为什么应该全局安装 YAML 文件？

1.  什么是 SPA？

1.  处理`.vue`文件时，应该在哪里添加 Vue.js 的加载器？

1.  以下代码行缺少什么？

`import 'angular/http';`

1.  在使用 Angular 时，如何加载`app.js`？

1.  什么是 YARN？

1.  默认的`pkg.module`文件用于什么？


# 第六章：生产、集成和联合模块

在本章中，我们将涵盖生产、集成和联合模块。我们将概述正确的部署程序、快捷方式和替代方案。尽管本章的一些内容已经在更多细节上进行了讨论，但再次复习一下是很好的，这样您就可以更清楚地了解到目前为止学到的内容。

到目前为止，我们已经讨论并执行了开发构建，并暗示要进入生产，但适当的发布级生产过程有点不同，涉及交叉检查和遵循最佳实践。

本书的这一部分将探讨我们可以使用的各种选项，以部署 Webpack 5 与各种 Web 实用程序。这将为您提供这些 Web 实用程序的概述，并解释哪些对于特定情况和平台更为合适，包括使用 Babel 进行部署。

所有这些主题都与我们在生产捆绑的开头部分相关，该部分还涵盖了生产和发布目的的部署主题。

在本章中，我们将涵盖以下主题：

+   生产设置

+   Shimming

+   渐进式 Web 应用程序

+   集成任务运行器

+   GitHub

+   提取样板

+   模块联合

# 生产设置

现在我们了解了基础知识，我们可以继续学习如何实际部署生产捆绑包。在开发模式和生产模式下构建项目的目标有很大的不同。在生产模式下，目标转向使用轻量级源映射对构建进行最小化，并优化资产以提高加载时间。在开发模式下，强大的源映射至关重要，以及具有**localhost**服务器和实时重新加载或热模块替换。由于它们的不同目的，通常建议为每种模式编写单独的 Webpack 配置。

尽管它们之间存在差异，但通用配置应该在模式之间保持一致。为了合并这些配置，可以使用一个叫做`webpack-merge`的实用工具。这个通用配置过程意味着代码不需要在每个模式下重复。让我们开始吧：

1.  首先打开命令行工具，安装`webpack-merge`，并以开发模式保存它，如下所示：

```js
npm install --save-dev *webpack-merge*
```

1.  现在，让我们来看一下**项目目录**。它的内容应该结构类似于以下内容：

```js
 webpack5-demo
  |- package.json
  |- webpack.config.js
  |- webpack.common.js
  |- webpack.dev.js
  |- webpack.prod.js
  |- /dist
  |- /src
    |- index.js
    |- math.js
  |- /node_modules
```

请注意，前面的输出显示了在这个特定示例中存在额外的文件。例如，我们在这里包括了`webpack.common.js`文件。

1.  让我们仔细看一下`webpack.common.js`文件：

```js
  const path = require('path');
  const { CleanWebpackPlugin } = require('clean-webpack-plugin');
  const HtmlWebpackPlugin = require('html-webpack-plugin');

  module.exports = {
    entry: {
      app: './src/index.js'
    },
    plugins: [
      // new CleanWebpackPlugin(['dist/*']) for < v2 versions of 
      // CleanWebpackPlugin
      new CleanWebpackPlugin(),
      new HtmlWebpackPlugin({
        title: 'Production'
      })
    ],
    output: {
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, 'dist')
    }
  };
```

`webpack.common.js`文件处理**CommonJS**请求。它的做法与 ECMAScript 类似，但格式不同。让我们确保在**ECMA**环境中工作的`webpack.config.js`文件与**CommonJS**配置文件做同样的事情。注意入口点和捆绑名称，以及**`title`**选项。后者是模式的对应项，因此您必须确保项目中的两个文件之间存在对等性。

1.  在这里，我们来看一下`webpack.dev.js`文件：

```js
  const merge = require('webpack-merge');
  const common = require('./webpack.common.js');

  module.exports = merge(common, {
    mode: 'development',
    devtool: 'inline-source-map',
    devServer: {
      contentBase: './dist'
    }
  });
```

正如您所看到的，前面的代码提供了关于如何在开发模式下使用`webpack.common.js`的说明。这只是一个交叉检查的情况，以确保您的工作内容在最终生产中格式正确，并且在编译过程中不会出现错误。

1.  如果您正在生产模式下工作，将调用以下文件`webpack.prod.js`：

```js
  const merge = require('webpack-merge');
  const common = require('./webpack.common.js');

  module.exports = merge(common, {
    mode: 'production',
  });
```

使用`webpack.common.js`，设置入口和输出配置，并包括在两种环境模式下都需要的任何插件。在使用`webpack.dev.js`时，模式应设置为开发模式。还要在该环境中添加推荐的**devtool**，以及简单的`devServer`配置。在`webpack.prod.js`中，模式当然设置为生产模式，加载`TerserPlugin`。

请注意，`merge()` 可以在特定环境配置中使用，以便您可以轻松地在开发和生产模式中包含通用配置。值得注意的是，在使用 `**webpack-merge**` 工具时还有各种高级功能可用。

1.  让我们在 **`webpack.common.js`** 中进行这些开发配置：

```js
  { 
   "name": "development", 
   "version": "1.0.0", 
   "description": "", 
   "main": "src/index.js",
   "scripts": { 
   "start": "webpack-dev-server --open --config webpack.dev.js", 
   "build": "webpack --config webpack.prod.js" 
  }, 
    "keywords": [], 
    "author": "", 
    "license": "ISC", 
    "devDependencies": { 
      "clean-webpack-plugin": "⁰.1.17", 
      "css-loader": "⁰.28.4", 
      "csv-loader": "².1.1", 
      "express": "⁴.15.3",
      "file-loader": "⁰.11.2", 
      "html-webpack-plugin": "².29.0", 
      "style-loader": "⁰.18.2", 
      "webpack": "⁵.0.0",
      "webpack-dev-middleware": "¹.12.0",
      "webpack-dev-server": "².9.1", 
      "webpack-merge": "⁴.1.0", 
      "xml-loader": "¹.2.1"
   } 
 }
```

前面的示例只是展示了 CommonJS 的完成配置。请注意通过 `devDependancies` 选项加载的插件依赖项及其版本列表。

1.  现在，运行这些脚本，看看输出如何变化。

1.  以下代码显示了如何继续添加到生产配置：

```js
 document.body.appendChild(component());
```

请注意，当处于生产模式时，Webpack 5 将默认压缩项目的代码。

`TerserPlugin` 是开始压缩的好地方，应该作为默认选项使用。然而，还有一些选择，比如 `BabelMinifyPlugin` 和 `closureWebpackPlugin`。

尝试不同的压缩插件时，请确保选择也会删除任何死代码，类似于我们在本书中早些时候描述的摇树。与摇树相关的是 shimming，我们将在下面讨论。

# Shimming

Shimming，或者更具体地说，`shim-loaders`。现在是深入探讨这个概念的好时机，因为在您继续之前，您需要牢牢掌握它。

Webpack 使用的编译器可以理解用 **ECMAScript** **2015**，**CommonJS** 或 **AMD** 编写的模块。值得注意的是，一些第三方库可能需要全局依赖，例如使用 jQuery 时。在这种情况下，这些库可能需要导出全局变量。模块的这种几乎破碎的特性是 Shimming 发挥作用的地方。

Shimming 可以让我们将一种语言规范转换为另一种。在 Webpack 中，这通常是通过专门针对您的环境的加载器来完成的。

Webpack 的主要概念是模块化开发的使用 - 孤立的模块，安全地包含，不依赖于隐藏或全局依赖关系 - 因此重要的是要注意，使用这样的依赖关系应该是稀少的。

当您希望对浏览器进行 polyfill 以支持多个用户时，Shimming 可以派上用场。在这种情况下，polyfill 只需要在需要的地方进行修补并按需加载。

Shimming 与修补有关，但往往发生在浏览器中，这使得它与渐进式网络应用程序高度相关。

在下一节中，我们将更详细地了解渐进式网络应用程序 - 它们对于 Webpack 5 非常重要。

# 渐进式网络应用

有时被称为 PWA，渐进式网络应用程序在线提供原生应用程序体验。它们有许多 contributing 因素，其中最显著的是应用程序在脱机和在线时都能正常运行的能力。为此，使用了服务工作者。

使您的网络应用程序能够脱机工作将意味着您可以提供诸如推送通知之类的功能。这些丰富的体验也将通过诸如服务工作者之类的设备提供给基于网络的应用程序。此脚本将在浏览器的后台运行，无论用户是否在正确的页面上，都会允许这些相同的通知甚至后台同步。

PWA 提供了网络的覆盖范围，但速度快、可靠，类似于桌面应用程序。它们也可以像移动应用一样引人入胜，并且可以提供相同的沉浸式体验。这展示了应用程序的新质量水平。它们也可以在跨平台兼容性中发挥作用。

响应式设计是网络朝这个方向的第一次推动，但使互联网更普遍的推动使我们走向了 PWA。为了发挥应用程序的潜力，您应该采用渐进式的方法。有关更多信息，请参阅 Google 关于此主题的资源：[`developers.google.com/web/progressive-web-apps/`](https://developers.google.com/web/progressive-web-apps/)。

在使用 Webpack 时，需要注册服务工作者，以便您可以开始将桌面功能集成到基于 Web 的 PWA 中。PWA 并不是为用户本地安装而设计的；它们通过 Web 浏览器本地工作。

通过将以下内容添加到您的代码中，可以注册服务工作者 - 在本例中，这是一个`index.js`文件：

```js
  if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/service-
      worker.js').then(registration => {
       console.log('SW registered: ', registration);
    }).catch(registrationError => {
     console.log('SW registration failed: ', registrationError);
    });
  });
 }
```

完成后，运行`npm build` - 您应该在命令行窗口中看到以下输出：

```js
SW registered
```

现在，应用程序可以在命令行界面中使用`npm start`来提供服务。

PWA 应该有一个清单、一个服务工作者，可能还有一个 workbox 来包装和保护服务工作者。有关清单的更多信息，请参见第三章，*使用配置和选项*。Workbox 是一个可以使用以下命令在命令行中安装的插件：

```js
npm install workbox-webpack-plugin --save-dev
```

在假设的`webpack.config.js`文件中，可以在此处看到**Workbox**插件的示例配置：

```js
const WorkboxPlugin = require('workbox-webpack-plugin');
new WorkboxPlugin.GenerateSW({
 clientsClaim: true,
 skipWaiting: true,
 }),
```

大括号`{`内的选项将鼓励服务工作者迅速到达该点，并且不允许它们扼杀先前的服务工作者。

随着项目变得更加复杂，您可能会考虑使用相关的任务运行器。让我们更详细地看一下这一点。

# 集成任务运行器

任务运行器处理自动化任务，如代码检查。Webpack 并不是为此目的而设计的 - 没有捆绑器是。然而，使用 Webpack，我们可以从任务运行器提供的高度关注度中受益，同时仍然具有高性能的捆绑。

虽然任务运行器和捆绑器之间存在一些重叠，但如果正确处理，它们可以很好地集成。在本节中，我们将探讨一些最流行的任务运行器的集成技术。

捆绑器通过准备 JavaScript 和其他前端代码以进行部署，转换其格式，使其适合于浏览器交付。例如，它允许我们将 JavaScript 拆分成块以进行延迟加载，从而提高性能。

捆绑可能是具有挑战性的，但其结果将消除许多繁琐的工作过程。

在本节中，我们将向您展示如何集成以下内容：

+   Gulp

+   Mocha

+   Karma

Gulp 可能是最知名的任务运行器，因此让我们首先从那里开始。它通过使用专用文件来利用，就像其他两个任务运行器一样。在这里，`gulpfile.js`文件将处理 Webpack 与 Gulp 的相互作用。让我们看看如何集成所有这些任务运行器：

1.  首先，让我们看一下`gulpfile.js`文件：

```js
const gulp = require('gulp'); 
const webpack = require('webpack-stream'); 
gulp.task('default', function() { 
   return gulp.src('src/entry.js') 
    .pipe(webpack({ 
 // Any configuration options... 
    })) 
 .pipe(gulp.dest('dist/')); 
});
```

这就是我们使用 Gulp 所需要做的。请注意`gulp.task`函数的使用，`return`入口点以及`.pipe(**gulp**.dest('dist/'));`输出位置。

1.  以下是您可以使用的命令行代码来安装 Mocha：

```js
npm install --save-dev *webpack mocha mocha-webpack*
*mocha-webpack* 'test/**/*.js'
```

有关更多信息，请访问 Webpack 社区存储库。

1.  以下是您需要对`karma.config.js`文件进行的配置文件修改，以便与 Webpack 一起使用 Karma：

```js
module.exports = function(config) {
  config.set({
    files: [
      { pattern: 'test/*_test.js', watched: false },
      { pattern: 'test/**/*_test.js', watched: false }
    ],
    preprocessors: {
      'test/*_test.js': [ 'webpack' ],
      'test/**/*_test.js': [ 'webpack' ]
    },
    webpack: {
      // Any custom webpack configuration...
    },
    webpackMiddleware: {
      // Any custom webpack-dev-middleware configuration...
    }
  });
};
```

`webpack`和`webpackMiddleware`选项已留空，以便您可以使用项目的特定配置填充此内容。如果您不使用它们，这些选项可以完全删除。出于本例的目的，我们不会这样做。

如果您希望在开发环境中使用它们，这些安装过程将对您有所帮助，但 GitHub 是一个越来越重要的工具。我们将在下一节中看一下它如何在开发中发挥关键作用。

# GitHub

如您可能已经知道的那样，GitHub 是一个与 Webpack 配合良好的命令行代码托管平台。在使用 Webpack 时，您将与 GitHub 托管的大部分代码和项目一起工作。

GitHub 基于 Git 版本控制系统。使用 GitHub 与 Webpack 5 允许在线使用一些命令行操作。

Git 命令行指令通常在每个新条目和每个命令之前使用`git`命令。Webpack 的大部分内容文件都可以通过 GitHub 获得，GitHub 的 Webpack 页面可以在这里找到：[`github.com/webpack/webpack`](https://github.com/webpack/webpack)。Webpack 5 的开发可以在这里查看其进展阶段，这可能会很有趣，并且可以让您更好地预期其到来，如果您需要升级您的项目。其 URL 为[`github.com/webpack/webpack/projects/5.`](https://github.com/webpack/webpack/projects/5)

作为开发人员，您可能经常使用 GitHub，但如果您是一名专注于 JavaScript 开发的开发人员，您可能经验有限。在处理 Webpack 项目时，GitHub 平台提供了大量的实时和协作机会。由于提供了版本控制和命令行功能，因此在本地执行软件开发的需求较少。这是 GitHub 在开发人员社区中如此受欢迎并成为开发人员工作证明的主要原因。

GitHub 允许开发人员共同在项目上工作。在处理捆绑项目时，这更加有用，因为一些命令行操作可以在线运行。GitHub 还允许敏捷工作流程或项目管理界面。敏捷方法允许团队通过专用数字平台进行协作，个人自组织。

在使用 GitHub 时，您可能会使用其他人的代码。这可能包括由团队开发的代码框架。即使是经验丰富的开发人员，如果他们对使用的逻辑不熟悉，这也可能变得非常困难。这就引出了样板的主题，通常是标准或有良好文档记录的代码，但尽管如此，您可能希望从项目中提取出这部分。这就是提取过程开始变得非常有用的地方。

# 提取样板

样板代码是需要包含在各个地方的代码部分，但几乎没有或没有进行修改。在使用被认为冗长的语言时，通常需要编写大量的代码。这一大段代码称为样板。它本质上与框架或库具有相同的目的，这些术语经常混淆或相互接受。

Webpack 社区提供了样板安装，例如安装多个常见依赖项的组合安装，如先决条件和加载程序。这些样板有多个版本，使用它们可以加快构建速度。请搜索 Webpack 社区页面（[`webpack.js.org/contribute/`](https://webpack.js.org/contribute/)）或 Webpack 的 GitHub 页面（[`github.com/webpack-contrib`](https://github.com/webpack-contrib)）以获取示例。

也就是说，有时只需要部分样板。为此，可能需要提取 Webpack 的样板功能。

在使用其最小化方法时，Webpack 允许提取样板；也就是说，只有您需要的样板元素包含在捆绑包中。这是在编译过程中自动完成的过程。

缩小是 Webpack 5 提供这种提取过程的关键方式，也是这种类型的捆绑器可以使用的更显著的方式之一。还有另一个关键过程，对于 Webpack 5 来说是非常有用的，也是本地的。它带我们走向了捆绑包的不同方向，但是这是一个毫无疑问会从一个复杂或自定义的构建中跟随的过程，比如一个从模板开始提取的项目。这个过程被称为模块联邦。

# 模块联邦

模块联邦已被描述为 JavaScript 架构的一个改变者。它基本上允许应用程序在服务器之间运行远程存储的模块代码，同时作为捆绑应用程序的一部分。

一些开发人员可能已经了解一种称为**GraphQL**的技术。它基本上是一个由 Apollo 公司开发的用于在应用程序之间共享代码的解决方案。联邦模块是 Webpack 5 的一个功能，允许捆绑应用程序之间发生这种情况。

长期以来，最好的折衷方案是使用`DllPlugin`的外部依赖，它依赖于集中的外部依赖文件，但是这对于有机开发、便利性或大型项目来说并不理想。

使用模块联邦，JavaScript 应用程序可以在应用程序之间动态加载代码并共享依赖关系。如果一个应用程序在其构建中使用了联邦模块，但需要一个依赖项来提供联邦代码，Webpack 也可以从联邦构建的原始位置下载该依赖项。因此，联邦将有效地提供 Webpack 5 可以找到所需依赖代码的地图。

在考虑联邦时，有一些术语需要考虑：远程和主机。远程一词指的是加载到用户应用程序中的应用程序或模块，而主机指的是用户在运行时通过浏览器访问的应用程序。

联邦方法是为独立构建设计的，可以独立部署或在您自己的存储库中部署。在这种意义上，它们可以双向托管，有效地作为远程内容的主机。这意味着单个项目可能在用户的旅程中在托管方向之间切换。

# 构建我们的第一个联邦应用

让我们首先看一下三个独立的应用程序，分别标识为第一个、第二个和第三个应用程序。

# 我们系统中的第一个应用程序

让我们从配置第一个应用程序开始：

1.  我们将在 HTML 中使用`<app>`容器。这个第一个应用程序是联邦系统中的远程应用程序，因此将被其他应用程序消耗。

1.  为了暴露应用程序，我们将使用`AppContainer`方法：

```js
const HtmlWebpackPlugin = require("html-webpack-plugin");
const ModuleFederationPlugin =
   require("webpack/lib/container/ModuleFederationPlugin");

module.exports = {
  plugins: [
   new ModuleFederationPlugin({
    name: "app_one_remote",
    remotes: {
      app_two: "app_two_remote",
      app_three: "app_three_remote"
 },
 exposes: {
   'AppContainer':'./src/App'
 },
 shared: ["react", "react-dom","react-router-dom"]
 }),
 new HtmlWebpackPlugin({
   template: "./public/index.html",
   chunks: ["main"]
  })
 ]
} 
```

这个第一个应用程序还将消耗系统中其他两个联邦应用程序的组件。

1.  为了允许这个应用程序消耗组件，需要指定远程范围。

1.  所有这些步骤都应按照前面的代码块中指定的方式进行。

1.  现在，让我们来看一下构建的 HTML 部分：

```js
<head>
  <script src="img/app_one_remote.js"></script>
  <script src="img/app_two_remote.js"></script>
</head>
<body>
  <div id="root"></div>
</body>
```

前面的代码显示了 HTML 的`<head>`元素。`app_one_remote.js`在运行时连接运行时和临时编排层。它专门设计用于入口点。这些是示例 URL，您可以使用自己的位置。重要的是要注意，这个例子是一个非常低内存的例子，您的构建可能会大得多，但足够好理解这个原则。

1.  为了消耗远程应用程序的代码，第一个应用程序有一个网页，从第二个应用程序中消耗对话框组件，如下所示：

```js
const Dialog = React.lazy(() => import("app_two_remote/Dialogue")); 
const Page1 = () => { 
  return ( 
    <div> 
      <h1>Page 1</h1> 
        <React.Suspense fallback="Loading User Dialogue..."> 
          <Dialog /> 
        </React.Suspense> 
    </div> 
  ); 
}
```

1.  让我们从导出我们正在使用的默认 HTML 页面开始，并设置路由，操作如下：

```js
import { Route, Switch } from "react-router-dom";
import Page1 from "./pages/page1";
import Page2 from "./pages/page2";
import React from "react";
   const Routes = () => (
     <Switch>
       <Route path="/page1">
        <Page1 />
       </Route>
       <Route path="/page2">
        <Page2 />
       </Route>
     </Switch>
  );
```

前面的代码块显示了代码如何工作；它将从我们正在开发的系统中的每个页面导出默认路由。

这个系统是由三个应用程序组成的，我们现在来看第二个应用程序。

# 第二个应用程序

我们正在构建的系统由三个应用程序组成。这个应用程序将暴露对话框，使得这个序列中的第一个应用程序可以消耗它。然而，第二个应用程序将消耗第一个应用程序的`<app>`元素标识符。让我们来看一下：

1.  我们将从配置第二个应用程序开始。这意味着我们需要指定`app-one`作为远程应用程序，并同时演示双向托管：

```js
 const HtmlWebpackPlugin = require("html-webpack-plugin");
 const ModuleFederationPlugin =
   require("webpack/lib/container/ModuleFederationPlugin");
 module.exports = {
   plugins: [
     new ModuleFederationPlugin({
     name: "app_two_remote",
     library: { type: "var", name: "app_two_remote" },
     filename: "remoteEntry.js",
     exposes: {
       Dialog: "./src/Dialogue"
 },
   remotes: {
     app_one: "app_one_remote",
 },
   shared: ["react", "react-dom","react-router-dom"]
 }),
 new HtmlWebpackPlugin({
   template: "./public/index.html",
   chunks: ["main"]
  })
 ]
};
```

1.  为了消耗，以下是根应用程序的样子：

```js
import React from "react";
import Routes from './Routes'
const AppContainer = React.lazy(() =>
  import("app_one_remote/AppContainer"));

const App = () => {
  return (
   <div>
     <React.Suspense fallback="Loading App Container from Host">
       <AppContainer routes={Routes}/>
     </React.Suspense>
   </div>
  );
}
```

1.  接下来，我们需要设置代码，以便我们可以导出默认的应用程序。以下是使用对话框时默认页面应该看起来的示例：

```js
import React from 'react'
import {ThemeProvider} from "@material-ui/core";
import {theme} from "./theme";
import Dialog from "./Dialogue";

function MainPage() {
   return (
     <ThemeProvider theme={theme}>
       <div>
         <h1>Material User Iinterface App</h1>
         <Dialog />
      </div>
     </ThemeProvider>
  );
}
```

1.  现在，我们需要导出默认的`MainPage`。这是通过我们系统中的第三个应用程序完成的。

# 第三个应用程序

让我们来看看我们的第三个和最后一个应用程序：

1.  我们系统中的第三个应用程序将导出一个默认的`MainPage`。这是通过以下脚本完成的：

```js
new ModuleFederationPlugin({
   name: "app_three_remote",
   library: { type: "var", name: "app_three_remote" },
   filename: "remoteEntry.js",
   exposes: {
     Button: "./src/Button"
 },
 shared: ["react", "react-dom"]
}),
```

如预期的那样，第三个应用程序看起来与之前的应用程序类似，只是它不从第一个应用程序中消耗`<app>`。这个应用程序是独立的，没有导航，因此不指定任何远程联邦组件。

在浏览器中查看系统时，您应该密切关注网络选项卡。代码可以在三个不同的服务器（可能）和三个不同的捆绑包（自然）之间进行联邦。

这个组件允许您的构建具有很大的动态性，但除非您希望利用**服务器端渲染（SSR）**或渐进式加载，否则您可能希望避免联邦整个应用程序容器，否则加载时间可能会受到严重影响。

加载问题是一个自然的关注点，但通常会导致项目规模变大的一个问题是潜在的重复的重复代码，这是使用多个并行捆绑的结果。让我们来看看 Webpack 5 是如何处理这个问题的。

# 重复问题

Webpack 的一个关键特性是去除重复的代码。在联邦环境中，宿主应用程序为远程应用程序提供依赖项。在没有可共享的依赖项的情况下，远程应用程序可以自动下载自己的依赖项。这是一种内置的冗余故障安全机制。

在大规模情况下手动添加供应商代码可能会很繁琐，但联邦功能允许我们创建自动化脚本。这是开发者的选择，但这可能是一个很好的机会，让您能够测试自己的知识。

我们已经提到了 SSR。您应该知道服务器构建需要一个`commonjs`库目标，以便它们可以与 Webpack 联邦一起使用。这可以通过 S3 流式传输、ESI，或者通过自动化 npm 发布来完成，以便您可以消耗服务器变体。以下代码显示了包括`commonjs`的一个示例：

```js
module.exports = {
 plugins: [
  new ModuleFederationPlugin({
    name: "container",
    library: { type: "commonjs-module" },
    filename: "container.js",
    remotes: {
      containerB: "../1-container-full/container.js"
 },
   shared: ["react"]
  })
 ]
};
```

您可能希望使用`target: "node"`方法，以避免 URL 而选择文件路径。这将允许在为 Node.js 构建时使用相同的代码库但不同的配置进行 SSR。这也意味着单独的构建将成为单独的部署。

作为一家公司，Webpack 愿意展示 SSR 示例，您作为开发者社区的一部分可能已经制作了。他们将很乐意通过他们的 GitHub 页面接受拉取请求，因为他们有带宽，并且在这个过程中受益于曝光。

# 总结

在本章中，您了解了部署项目在线的过程。我们讨论了安装和设置过程，以及树摇。

首先，我们看了一下生产和开发模式，每种环境的性质，以及它们如何利用 Webpack。然后，我们看了 shimming，最佳使用方法，它的工作原理，以便我们可以修补代码，它与任务运行器的关系，以及它们与 Webpack 等打包工具的集成。

现在，你应该能够提取 boilerplate，集成各种任务运行器，并知道如何使用 GitHub。

在下一章中，我们将讨论热模块替换和实时编码，并掌握一些严肃的教程。

# 问题

1.  术语 boilerplate 是什么意思？

1.  摇树是做什么的？

1.  术语 shimming 是什么意思？

1.  渐进式 Web 应用的目的是什么？

1.  任务运行器的作用是什么？

1.  这一章提到了哪三个任务运行器？

1.  Webpack 的编译器可以理解哪三种规范编写的模块？

# 进一步阅读

+   Webpack 内容文件和 GitHub 的 Webpack 页面可以在这里找到：[`github.com/webpack/webpack`](https://github.com/webpack/webpack)。

+   Webpack 5 可以从这里按照其进展阶段进行查看：[`github.com/webpack/webpack/projects/5.`](https://github.com/webpack/webpack/projects/5)

+   Webpack 社区页面：[`webpack.js.org/contribute/`](https://webpack.js.org/contribute/)

+   Webpack 的 GitHub 页面：[`github.com/webpack-contrib`](https://github.com/webpack-contrib)


# 第七章：调试和迁移

本章将进一步探讨迁移和调试，提供对这些主题的广泛概述和详细检查。

迁移是指将内容和项目从 Webpack 的早期版本迁移到较新版本的过程。我们将特别关注从 Webpack 3 版本迁移到 4 版本以及从 4 版本迁移到 5 版本的过程。我们还将介绍如何处理已弃用的插件以及如何删除或更新它们。这将包括在使用 Node.js v4 和 CLI 时的迁移。

本章将讨论`resolve`方法以及`module.loaders`现已被`module.rules`方法取代。它还将涵盖加载器的链接，包括不再需要或已删除的加载器的链接。

然后，本章将继续探讨调试。调试涉及消除复杂软件系统中出现的常见故障和错误的过程。本章将解释常见问题及其解决方案、故障排除、避免这些问题的最佳实践以及如何找到故障。

本章涵盖的主题如下：

+   调试

+   热模块替换

+   添加实用程序

+   迁移

# 调试

调试工具对于工作流程至关重要，特别是在贡献核心复制、编写加载器或任何其他复杂形式的编码时。本指南将带您了解在解决诸如性能缓慢或不可原谅的回溯等问题时最有用的实用工具。

+   通过 Node.js 和 CLI 提供的`stats`数据

+   通过`node-nightly`和最新的 Node.js 版本使用 Chrome DevTools

在 Webpack 5 中，截至撰写本文时，存在一些已知问题；例如，DevTools 不支持持久缓存和包含绝对路径的持久缓存文件尚不可移植。

在调试构建问题、手动筛选数据或使用工具时，`stats`数据非常有用。它可用于查找以下内容：

+   构建错误和警告

+   每个模块的内容

+   模块编译和解析统计

+   模块之间的相互关系

+   任何给定块中包含的模块

此外，官方的 Webpack 分析工具将接受这些数据并为您可视化。

有时，当控制台语句无法完成工作时，需要更强大的解决方案。

正如前端开发人员社区中普遍认为的那样，Chrome DevTools 在调试应用程序时是不可或缺的，但它并不止步于此。从 Node.js v6.3.0+开始，开发人员可以使用内置的检查标志在 DevTools 中调试 Node.js 程序。

这个简短的演示将利用`node-nightly`包，该包提供了最新的检查功能。这提供了创建断点、调试内存使用问题、在控制台中公开对象等功能：

1.  首先全局安装`node-nightly`包：

```js
npm install --global node-nightly
```

1.  现在必须使用命令行来运行此包以完成安装：

```js
node-nightly
```

1.  现在，使用`node-nightly`的`inspect`标志功能，我们可以开始调试任何 Webpack 项目。需要注意的是，现在无法运行 npm 脚本；相反，需要表达完整的`node_module`路径：

```js
node-nightly --inspect ./node_modules/webpack/bin/webpack.js
```

1.  输出应该在命令行实用程序窗口中显示如下内容：

```js
Debugger listening on ws://127.0.0.1:9229/c624201a-250f-416e-a018-300bbec7be2c For help see https://nodejs.org/en/docs/inspector
```

1.  现在，转到 Chrome 的检查功能（`chrome://inspect`），任何活动脚本现在应该在`远程目标`标题下可见。

单击每个脚本下的“检查”链接将在会话中为节点打开专用的调试器或 DevTools 链接，这将自动连接。请注意，NiM 是 Chrome 的一个方便的扩展，每次进行检查时都会自动在新标签中打开 DevTools。这对于较长的项目非常有用。

还可以使用`inspect-brk`标志，它会在任何脚本的第一个语句上中断，允许查看源代码，设置断点，并临时停止和启动进程。这也允许程序员继续向所讨论的脚本传递参数；这可能对进行并行配置更改很有用。

所有这些都与一个关键功能有关，这也是本指南中先前提到的令人兴奋的**热模块替换**（HMR）主题。下一节将介绍它是什么以及如何使用它，以及教程。

# 热模块替换

HMR 可能是 Webpack 中最有用的元素。它允许运行时更新需要完全刷新的模块。本节将探讨 HMR 的实现，以及它的工作原理和为什么它如此有用。

非常重要的一点是，HMR 不适用于生产模式，也不应该在生产模式下使用；它只应该在开发模式下使用。

值得注意的是，根据开发人员的说法，插件的内部 HMR API 在将来的 Webpack 5 更新中可能会发生变化。

要启用 HMR，我们首先需要更新我们的`webpack-dev-server`配置，并使用 Webpack 内置的 HMR 插件。这个功能对提高生产力非常有用。

删除`print.js`的入口点也是一个好主意，因为它现在将被`index.js`模块使用。

任何使用`webpack-dev-middleware`而不是`webpack-dev-server`的人现在应该使用`webpack-hot-middleware`包来启用 HMR：

1.  要开始使用 HMR，我们需要返回到配置文件`webpack.config.js`。按照这里的修改：

```js
  const path = require('path');
  const HtmlWebpackPlugin = require('html-webpack-plugin');
  const CleanWebpackPlugin = require('clean-webpack-plugin');
  const webpack = require('webpack');

  module.exports = {
    entry: {
       app: './src/index.js',
       print: './src/print.js'
       app: './src/index.js'
    },
    devtool: 'inline-source-map',
    devServer: {
      contentBase: './dist',
 hot: true
    },
    plugins: [
      // new CleanWebpackPlugin(['dist/*']) for < v2 versions of 
      // CleanWebpackPlugin
      new CleanWebpackPlugin(),
      new HtmlWebpackPlugin({
        title: 'Hot Module Replacement'
      }),
      new webpack.HotModuleReplacementPlugin()
    ],
    output: {
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, 'dist')
    }
  };
```

请注意前面代码中的添加——`hot:`选项设置为`true`，并添加了`'Hot Module Replacement'`插件，以及在 HMR 配置中创建新的 Webpack 插件。所有这些都应该被做来使用插件和 HMR。

1.  可以使用命令行修改`webpack-dev-server`配置，命令如下：

```js
webpack-dev-server --hot 
```

这将允许对捆绑应用程序进行临时更改。

1.  `index.js`现在应该更新，以便当检测到`print.js`的更改时，Webpack 可以接受更新的模块。更改在以下示例中以粗体显示;我们只是用`import`表达式和函数暴露`print.js`文件：

```js
  import _ from 'lodash';
 import printMe from './print.js';

  function component() {
    const element = document.createElement('div');
    const btn = document.createElement('button');

    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');

    btn.innerHTML = 'Click me and check the console!';
    btn.onclick = printMe;

    element.appendChild(btn);

    return element;
  }

  document.body.appendChild(component());

 if (module.hot) {
    module.hot.accept('./print.js', function() {
      console.log('Accepting the updated printMe module');
      printMe();
```

```js
    })
  }
```

如果您更改`print.js`中的控制台日志，则将在浏览器控制台中看到以下输出。现在，强制性的`printMe()`按钮已经消失，但稍后可以更新：

```js
  export default function printMe() {
    console.log('This got called from print.js!');
    console.log('Updating print.js...')
  }
```

查看控制台窗口应该会显示以下输出：

```js
[HMR] Waiting for update signal from WDS...
main.js:4395 [WDS] Hot Module Replacement enabled.
  2main.js:4395 [WDS] App updated. Recompiling...
  main.js:4395 [WDS] App hot update...
  main.js:4330 [HMR] Checking for updates on the server...
  main.js:10024 Accepting the updated printMe module!
  0.4b8ee77….hot-update.js:10 Updating print.js...
  main.js:4330 [HMR] Updated modules:
  main.js:4330 [HMR]  - 20
```

前面的代码块显示 HMR 正在等待来自 Webpack 的信号，如果发生 HMR，命令行实用程序可以执行自动捆绑修订。当命令行窗口保持打开时，它也会显示这一点。Node.js 有一个类似的 API 可以使用。

# 在使用 Node.js API 时使用 DevServer

在使用**DevServer**和 Node.js API 时，不应将`dev server`选项放在 Webpack 配置对象上；而应始终将其作为第二参数传递。

在这里，DevServer 只是指在开发模式下使用 Webpack，而不是`watching`或`production`模式。要在 Node.js API 中使用 DevServer，请按照以下步骤进行操作：

1.  该函数放在`webpack.config.js`文件中，如下：

```js
new WebpackDevServer(compiler, options)
```

要启用 HMR，首先必须修改配置对象以包括 HMR 入口点。`webpack-dev-server`包包括一个名为`addDevServerEntryPoints`的方法，可以用来执行此操作。

1.  接下来是使用`dev-server.js`的简短示例：

```js
const webpackDevServer = require('webpack-dev-server');
const webpack = require('webpack');

  const config = require('./webpack.config.js');
  const options = {
    contentBase: './dist',
    hot: true,
    host: 'localhost'
};

webpackDevServer.addDevServerEntrypoints(config, options);
const compiler = webpack(config);
const server = new webpackDevServer(compiler, options);

server.listen(5000, 'localhost', () => {
  console.log('dev server listening on port 5000');
});
```

HMR 可能很困难。为了证明这一点，在我们的示例中，单击在示例网页中创建的按钮。显然控制台正在打印旧函数。这是因为事件处理程序绑定到原始函数。

1.  为了解决这个问题以便与 HMR 一起使用，必须使用`module.hot.accept`更新绑定到新函数。请参阅以下示例，使用`index.js`：

```js
  import _ from 'lodash';
  import printMe from './print.js';

  function component() {
    const element = document.createElement('div');
    const btn = document.createElement('button');

    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');

    btn.innerHTML = 'Click me and view the console!';
    btn.onclick = printMe;  // onclick event is bind to the 
                            // original printMe function

    element.appendChild(btn);

    return element;
  }

  document.body.appendChild(component());
 let element = component(); // Store the element to re-render on 
                             // print.js changes
  document.body.appendChild(element);

  if (module.hot) {
    module.hot.accept('./print.js', function() {
      console.log('Accepting the updated printMe module!');
      printMe();
      document.body.removeChild(element);
 element = component(); 
      document.body.appendChild(element);
    })
  }
```

通过解释，`btn.onclick = printMe;`是绑定到原始`printMe`函数的`onclick`事件。`let element = component();`将存储元素以便在`print.js`发生任何更改时重新渲染。还要注意`element - component();`语句，它将重新渲染组件并更新单击处理程序。

这只是您可能会遇到的陷阱的一个例子。幸运的是，Webpack 提供了许多加载程序，其中一些稍后将讨论，这使得 HMR 变得不那么棘手。现在让我们来看看 HMR 和样式表。

# HMR 和样式表

使用`style-loader`可以更轻松地使用 HMR 处理 CSS。此加载程序使用`module.hot.accept`在更新 CSS 依赖项时修补样式标签。

在我们的实际示例的下一个阶段，我们将采取以下步骤：

1.  首先，使用以下命令安装两个加载程序：

```js
npm install --save-dev style-loader css-loader
```

1.  接下来，更新配置文件`webpack.config.js`以使用这些加载程序：

```js
  const path = require('path');
  const HtmlWebpackPlugin = require('html-webpack-plugin');
  const CleanWebpackPlugin = require('clean-webpack-plugin');
  const webpack = require('webpack');

  module.exports = {
    entry: {
      app: './src/index.js'
    },
    devtool: 'inline-source-map',
    devServer: {
      contentBase: './dist',
      hot: true
    },
    module: {
      rules: [
        {
 test: /\.css$/,
          use: ['style-loader', 'css-loader']
        }
      ]
    },
    plugins: [
      // new CleanWebpackPlugin(['dist/*']) for < v2 versions of 
        // CleanWebpackPlugin
      new CleanWebpackPlugin(),
      new HtmlWebpackPlugin({
        title: 'Hot Module Replacement'
      }),
      new webpack.HotModuleReplacementPlugin()
    ],
    output: {
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, 'dist')
    }
  };
```

热加载样式表就像将它们导入模块一样简单，您可以从前面的配置示例和接下来的目录结构示例中看到。

1.  确保按照以下结构组织项目文件和目录：

```js
 webpack5-demo
  | - package.json
  | - webpack.config.js
  | - /dist
    | - bundle.js
  | - /src
    | - index.js
    | - print.js
    | - styles.css
```

1.  通过向样式表添加`body`样式来将文档主体的背景与其关联的蓝色进行样式化。使用`styles.css`文件执行此操作：

```js
body {
  background: blue;
}
```

1.  之后，我们需要确保内容正确加载到`index.js`文件中，如下所示：

```js
  import _ from 'lodash';
  import printMe from './print.js';
 import './styles.css'; 
  function component() {
    const element = document.createElement('div');
    const btn = document.createElement('button');

    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');

    btn.innerHTML = 'Click me and check the console!';
    btn.onclick = printMe;  // onclick event is bind to the 
                            // original printMe function

    element.appendChild(btn);

    return element;
  }

  let element = component();
  document.body.appendChild(element);

  if (module.hot) {
    module.hot.accept('./print.js', function() {
      console.log('Accepting the updated printMe module!');
      document.body.removeChild(element);
      element = component(); // Re-render the "component" to update 
                             // the click handler
      document.body.appendChild(element);
    })
  }
```

现在，当`body`标签背景类的样式更改为红色时，颜色变化应立即注意到，无需刷新页面，表明了热编码的实时性。

1.  现在，您应该使用`styles.css`对背景进行这些更改：

```js
  body {
    background: blue;
    background: red;
  }
```

这以一种非常简单的方式演示了如何进行实时代码编辑。这只是一个简单的例子，但它是一个很好的介绍。现在，让我们进一步探讨一些更棘手的内容——加载程序和框架。

# 其他加载程序和框架

我们已经介绍了许多可用的加载程序，这些加载程序使 HMR 与各种框架和库更加顺畅地交互。其中一些更有用的加载程序在这里进行了描述：

+   **Angular HMR**：只需对主`NgModule`文件进行简单更改，即可完全控制 HMR API（不需要加载程序）。

+   **React Hot Loader**：此加载程序可以实时调整 React 组件。

+   **Elm Hot Webpack Loader**：此加载程序支持 Elm 编程语言的 HMR。

+   **Vue Loader**：此加载程序支持 Vue 组件的 HMR。

我们已经讨论了 HMR 和相关加载程序和框架，但有一件事我们尚未讨论——与我们迄今为止涵盖的内容相关的添加实用程序。我们将在接下来的部分中深入了解。

# 添加实用程序

在这种情况下，实用程序意味着负责一组相关功能的文件或模块，旨在优化、分析、配置或维护。这与应用程序形成对比，后者倾向于执行直接面向用户的任务或一组任务。因此，在这种情况下，您可以将实用程序视为前端的一部分，但它被隐藏在后台用于后台任务。

首先，在示例项目中添加一个实用程序文件。在`src/math.js`中执行此操作，以便导出两个函数：

1.  第一步将是组织项目目录：

```js
webpack5-demo
|- package.json
|- webpack.config.js
|- /dist
  |- bundle.js
  |- index.html
|- /src
  |- index.js
  |- math.js
|- /node_modules
```

**项目树**显示了您的文件和文件夹的外观，您将注意到其中一些新的添加，例如`math.js`。

1.  现在让我们更仔细地看一下`math.js`的编码：

```js
export function square(x) {
  return x * x;
}

export function cube(x) {
  return x * x * x;
}
```

您会发现它们是简单易导出的函数；它们将在稍后显现。

1.  还要确保在配置文件`webpack.config.js`中将 Webpack 模式设置为`development`，以确保捆绑包不被最小化：

```js
const path = require('path');

module.exports = {
  entry: './src/index.js',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
  },
  mode: 'development',
  optimization: {
    usedExports: true
  }
};
```

1.  有了这个，接下来更新入口脚本以利用其中一种新方法，并为简单起见删除`lodash`。这是使用`src/index.js`文件完成的：

```js
  import _ from 'lodash';
  import { cube } from './math.js';

  function component() {
    const element = document.createElement('div');
    const element = document.createElement('pre');

    // Lodash, now imported by this script
    element.innerHTML = _.join(['Hello', 'webpack'], ' ');
    element.innerHTML = [
      'Hello Webpack!',
      '5 cubed is equal to ' + cube(5)
    ].join('\n\n');

    return element;
  }

  document.body.appendChild(component());
```

从上面的例子中，我们可以看到`square`方法没有从`src/math.js`模块中导入。这个函数可以被视为死代码，基本上是一个未使用的导出，可以被删除。

1.  现在，再次运行`npm`构建以检查结果：

```js
npm run build
```

1.  完成后，找到`dist/bundle.js`文件——它应该在第 90-100 行左右。搜索文件以查找类似以下示例的代码，以便按照此过程进行：

```js
/* 1 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {
  'use strict';
  /* unused harmony export square */
  /* harmony export (immutable) */ __webpack_exports__['a'] = cube;
  function square(x) {
    return x * x;
  }

  function cube(x) {
    return x * x * x;
  }
});
```

在这个例子中，现在会看到一个`unused harmony export square`的注释。请注意，它没有被导入。但是，它目前仍然包含在捆绑包中。

1.  ECMA 脚本并不完美，因此重要的是向 Webpack 的编译器提供关于代码纯度的提示。`packages.json`属性将有助于处理这些副作用：

```js
{
  "name": "your-project",
  "sideEffects": false
}
```

上述代码不包含副作用；因此，应将该属性标记为`false`，以指示 Webpack 删除未使用的导出。

在这种情况下，副作用被定义为在导入时执行特殊行为的脚本，而不是暴露多个导出等。一个例子是影响全局项目并且通常不提供导出的**polyfills**。

1.  如果代码具有副作用，可以提供一个数组作为补救措施，例如以下示例：

```js
{
  "name": "your-project",
  "sideEffects": [
    "./src/some-side-effectful-file.js"
  ]
}
```

此示例中的数组接受相对和绝对模式。

1.  请注意，任何导入的文件都会受到摇树的影响。例如，如果使用`CSS-loader`导入 CSS 文件，则必须将其添加到副作用列表中，以防止在生产模式下意外删除它：

```js
{
  "name": "your-project",
  "sideEffects": [
    "./src/some-side-effectful-file.js",
    "*.css"
  ]
}
```

1.  最后，`sideEffects`也可以从`module.rules`配置选项中设置。因此，我们使用`import`和`export`语法排队将死代码删除，但我们仍然需要从捆绑包中删除它。要做到这一点，将`mode`配置选项设置为`production`。这是通过以下方式在配置文件**`webpack.config.js`**中完成的：

```js
const path = require('path');

module.exports = {
  entry: './src/index.js',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist')
  },
  mode: 'development',
  optimization: {
    usedExports: true
  }
  mode: 'production'
};
```

`--optimize-minimize`标志也可以用于启用`TerserPlugin`。现在我们已经了解了这一点，可以再次运行`npm`构建。

现在清楚地看到整个捆绑包已经被最小化和混淆。仔细观察会发现`square`函数已经消失；取而代之的是一个混淆的 cube 函数：

```js
function r(e){return e*e*e}n.a=r
```

通过最小化和摇树，我们的捆绑包现在小了几个字节！虽然在这个假设的例子中可能看起来不多，但在处理具有复杂依赖关系树的大型应用程序时，摇树可以显著减少捆绑包大小。

`ModuleConcatenationPlugin`是摇树功能的必需品。它通过使用`mode: "production"`来添加。如果您没有使用它，请记得手动添加`ModuleConcatenationPlugin`。

必须完成以下任务才能充分利用摇树功能：

+   使用 ES2015 模块语法（即`import`和`export`）。

+   确保没有编译器将您的 ECMAScript 语法转换为 CommonJS 模块。

+   在`package.json`文件中添加一个`sideEffects`属性。

+   使用`production`配置选项来启用各种优化，包括摇树和最小化。

在进行摇树时，通常有助于将您的应用程序视为一棵树。在这个类比中，源代码和库将分别是绿叶和树的活部分。然而，死代码将代表枯叶。摇动这棵树将删除现在无效的代码。

这在迁移时尤其重要，值得考虑。考虑到 Webpack 版本之间的代码弃用变化，重要的是在尝试任何类似操作之前使软件达到最佳状态。这将防止出现非常棘手的错误。

# 迁移

迁移涉及从一个 Webpack 版本迁移到另一个版本。这通常涉及升级到最新版本。作为 Web 开发人员，你可能已经知道在处理其他软件时会有一些棘手的问题，所以这一部分可能是一个重要的部分，也许在未来的开发过程中你可以参考一下。

为了提供更详细的指南，包括了从 Webpack 3.0 迁移到 Webpack 4.0 的迁移策略，所以让我们在继续到版本 5 之前先进行一下这部分。

# 从版本 3 迁移到版本 4 的先决条件

在我们开始从 Webpack 版本 3 迁移到 4 的项目之前，有几个先决条件需要澄清：

+   Node.js

+   命令行

+   插件

+   模式

对于使用 Node.js 版本 4 或更低版本的开发人员，升级到 Node.js 版本 6 或更高版本是必要的。在命令行方面，CLI 已经移动到一个名为`webpack-cli`的单独包中。在使用 Webpack 4 之前，你需要安装它。

在更新插件时，许多第三方插件需要升级到最新版本以确保兼容，所以请注意这一点。浏览项目以找到需要更新的插件也是一个好主意。另外，请确保将新的模式选项添加到你的配置中：

1.  首先在你的配置中将模式设置为`production`或`development`，根据配置类型而定，如下面的代码片段所示，使用`webpack.config.js`：

```js
module.exports = {
    mode: 'production',
}
```

还有一种替代方法，可以通过 CLI 传递模式，就像下面的例子一样：

```js
--mode production
```

前面的例子展示了通过命令行在`production`模式下进行 Webpack 命令的后半部分。下面的例子展示了在`development`模式下的相同情况：

```js
--mode development
```

1.  下一步是移除弃用的插件；这些插件应该从你的配置文件中移除，因为它们在生产模式下是默认的。下面的例子将向你展示如何在`webpack.config.js`中进行编辑：

```js
module.exports = {
 plugins: [
   new NoEmitOnErrorsPlugin(),
   new ModuleConcatenationPlugin(),
   new DefinePlugin({ "process.env.NODE_ENV":
     JSON.stringify("production") })
   new UglifyJsPlugin()
 ],
}
```

下面的例子让你看到了这在开发模式下是如何工作的。请注意，插件在开发模式下是默认的，同样使用`webpack.config.js`：

```js
module.exports = {
 plugins: [
   new NamedModulesPlugin()
 ],
}
```

1.  如果一切都做对了，你会发现已经移除了弃用的插件。你的配置文件**`webpack.config.js`**应该看起来像下面这样：

```js
module.exports = {
 plugins: [
   new NoErrorsPlugin(),
   new NewWatchingPlugin()
 ],
}
```

此外，在 Webpack 4.0 中，`CommonChunkPlugin`已被移除，并提供了`optimization.splitChunks`选项作为替代。

如果你正在从统计数据生成 HTML，现在可以使用`optimization.splitChunks.chunks: "all"`——这在大多数情况下是最佳配置。

关于`import()`和 CommonJS 还有一些工作要做。在 Webpack 4 中，使用`import()`加载任何非 ESM 脚本的结果已经发生了变化：

1.  现在，你需要访问默认属性来获取`module.exports`的值。在这里查看`non-esm.js`文件，看看它是如何运作的：

```js
module.exports = {
      sayHello: () => {
       console.log('Hello World');
     }
 };
```

这是一个简单的 JavaScript 函数，你可以复制它的内容来跟随演示并查看结果的变化。

1.  下一个文件是一个**`example.js`**文件。它可以被命名为任何你想要的名字，你可以执行任何你想要的操作。在这个例子中，它是一个简单的`sayHello();`函数：

```js
function sayHello() {
 import('./non-esm.js').then(module => {
  module.default.sayHello();
 });
}
```

这些代码块展示了如何使用 CommonJS 编写简单的函数。你应该将这种约定应用到你现有的代码中，以确保它不会出错。

1.  当使用自定义加载器转换`.json`文件时，现在需要在`webpack.config.js`中更改模块类型：

```js
module.exports = {
 rules: [
  {
    test: /config\.json$/,
    loader: 'special-loader',
    type: 'javascript/auto',
    options: {...}
  }
 ]
};
```

1.  即使使用`json-loader`，也可以将其移除；参见下面的例子：

```js
module.exports = {
  rules: [
   {
     test: /\.json$/,
     loader: 'json-loader'
   }
  ]
};
```

完成所有必需的迁移先决条件后，下一步是内置在 Webpack 中的自动更新过程。

# 从版本 4 迁移到版本 5 时的先决条件

本指南旨在帮助您在直接使用 Webpack 时迁移到 Webpack 5。如果您使用更高级的工具来运行 Webpack，请参考该工具的迁移说明。

如第一章中所解释的，*Webpack 5 简介*，Webpack 5 需要 Node.js 版本 10.13.0（LTS）才能运行；但是，使用更新版本可以进一步提高构建性能：

1.  在升级到主要版本时，应确保检查相关插件和加载程序的个别迁移说明，特别是通过作者提供的副本。在这种情况下，在构建过程中注意弃用警告。您可以通过这种方式调用 Webpack 来获取弃用警告的堆栈跟踪，以找出哪些插件和加载程序负责。Webpack 5 将删除所有已弃用的功能。要继续，构建过程中不应出现弃用警告。

1.  确保从统计数据中使用入口点信息。如果使用`HtmlWebpackPlugin`，则无需执行此步骤。

对于包含静态 HTML 或以其他方式创建静态 HTML 的构建，您必须确保使用入口点来生成任何脚本和链接任何 HTML 标签的统计 JSON 文件。如果不可能，您应该避免将`splitChunks.chunks`键设置为`all`，并且不要针对`splitChunks.maxSize`键设置任何设置。然而，这只是一个变通方法，可以被认为不是理想的解决方案。

1.  确保将模式设置为`production`或`development`，以确保设置相应模式的默认值。

1.  此外，如果您使用了以下选项，请确保将它们更新为更新版本：

```js
optimization.hashedModuleIds: true => optimization.moduleIds:
  'hashed'
optimization.namedChunks: true => optimization.chunkIds: 'named'
optimization.namedModules: true => optimization.moduleIds: 'named'
NamedModulesPlugin => optimization.moduleIds: 'named'
NamedChunksPlugin => optimization.chunkIds: 'named'
HashedModulesPlugin => optimization.moduleIds: 'hashed'
optimization.occurrenceOrder: true => optimization: { chunkIds:
   'total-size', moduleIds: 'size' }
optimization.splitChunks.cacheGroups.vendors =>
   optimization.splitChunks.cacheGroups.defaultVendors
```

1.  接下来，我们需要测试 Webpack 5 与您的应用程序的兼容性。为此，请为您的 Webpack 4 配置设置以下选项。如果在 Webpack 4 中没有任何构建错误，我们将知道任何后续故障是否是版本 5 独有的。这可能听起来很繁琐，但它可以消除递归故障查找：

```js
module.exports = {
 // ...
   node: {
     Buffer: false,
     process: false
   }
 };
```

在 Webpack 5 中，上述选项已从配置中删除，并默认设置为`false`。确保在 Webpack 4 测试构建中执行此操作，但在版本 5 构建中需要再次删除。

1.  接下来是一个简单和简洁的命令行执行，用于升级您的 Webpack 版本：

```js
npm: npm install webpack@next --dev
Yarn: yarn add webpack@next -D
```

现在，我们需要清理我们的配置。

建议您将配置中的`[hash]`占位符更改为`[contenthash]`。这已被证明更有效，并且可以帮助加固您的代码。

如果您正在使用`pnp-webpack-plugin`，它现在默认支持 Webpack 的版本 5，但现在需要从配置模式中删除。

`IgnorePlugin`现在接受一个选项对象，因此如果您将其用作正则表达式，则需要进行重写，例如以下内容：

```js
new IgnorePlugin({ resourceRegExp: /regExp/ }).
```

对于通过`import`使用 WASM 的开发人员，您应该通过将`experiments.syncWebAssembly`变量设置为`true`来启用已弃用的规范。这将在 Webpack 5 中设置与 Webpack 4 相同的行为。一旦您已经迁移到 Webpack 5，现在应该更改实验的值以使用 WASM 的最新规范——`{ asyncWebAssembly: true, importAsync: true }`。

在使用自定义配置时，还应注意将`name`值替换为`idHint`。

在 Webpack 5 中，不支持从 JSON 模块中导出命名的导出，并且会收到警告。要以这种方式导入任何内容，应该从`package.json`中使用`const[version]=package;`。

1.  现在，清理构建代码是一个好的做法。其中一部分是在使用`const compiler =webpack(...);`时关闭编译器。这可以通过`compiler.close();`来完成。

一旦运行构建，可能会出现一些问题。例如，模式验证可能会失败，Webpack 可能会退出并显示错误，或者可能会出现构建错误、构建警告或弃用警告。

在每种情况下，都会有一个破坏性变更说明或一个带有指令的错误消息，可以通过命令行获得，就像往常一样。

在弃用警告的情况下，可能会有很多弃用警告，因为 Webpack 5 是新的，插件需要时间来适应核心变化。在每个版本完成测试之前，应该忽略它们，这是一个良好的做法。

您可以通过使用`--no-deprecation`标志来隐藏弃用警告，例如`node --no-deprecation`。

插件和加载器的贡献者应该遵循弃用消息中的警告建议来改进他们的代码。

如果需要，您还可以关闭运行时代码中的 ES2015 语法。默认情况下，Webpack 的运行时代码使用 ES2015 语法来构建更小的包。如果您的构建目标环境不支持此语法，例如 IE 11，您需要将`output.ecmaVersion: 5`设置为恢复到 ES5 语法。

处理遗留问题将是向上迁移时面临的最大障碍，这一规则不仅适用于 Webpack 5。Webpack 5 具有一些功能，将使遗留平台用户的体验更加愉快。在项目规划中考虑的一种方法是持久缓存。

# 启用持久缓存

缓存当然是为了提高加载时间和加快性能而进行的数据的中间存储。持久缓存在数据库驱动项目中非常常见，从数据库中提取的数据会被缓存，以便用户拥有早期版本的副本。然后可以一次性加载，而不会对数据库造成太大的需求，因为数据的交付速度比基于服务器的文件条目要慢。

使用 Webpack 5，应用程序可以利用相同的操作并提高用户的加载速度，如果构建发生变化。

首先，要注意的是，持久缓存不是默认启用的。您必须选择使用它。这是因为 Webpack 5 更看重安全性而不是性能。启用即使提高了性能但会以任何小的方式破坏您的代码，这可能不是最好的主意。至少作为默认，此功能应保持禁用状态。

序列化和反序列化将默认工作；但是，开发人员可能会在缓存失效方面遇到麻烦。

缓存失效是指应用程序中有意更改时，例如开发人员更改文件的内容；在这种情况下，Webpack 会将旧内容的缓存视为无效。

Webpack 5 通过跟踪每个模块使用的`fileDependencies`、`contextDependencies`和`missingDependencies`来实现这一点。然后，Webpack 从中创建一个文件系统图。然后，文件系统与记录的副本进行交叉引用，这反过来会触发该模块的重建。

然后，输出包的缓存条目会为其生成一个标签；这本质上是所有贡献者的哈希。标签与缓存条目之间的匹配表示 Webpack 可以用于打包的内容。

Webpack 4 使用相同的过程进行内存缓存，而在 Webpack 5 中也可以工作，无需额外配置，除非启用了持久缓存。

您还需要在升级加载器或插件时使用`npm`，更改配置，更改要在配置中读取的文件，或者升级配置中使用的依赖项时，通过传递不同的命令行参数来运行构建，或者拥有自定义构建脚本并对其进行更改时，使缓存条目失效。

由于 Webpack 5 无法直接处理这些异常，因此持久缓存被作为一种选择性功能，以确保应用程序的完整性。

# Webpack 更新

有许多步骤必须采取，以确保 Webpack 的更新行为正确。与我们的示例相关的步骤如下：

+   升级和安装。

+   将模式添加到配置文件中。

+   添加 fork 检查器。

+   手动更新相关插件、加载器和实用程序。

+   重新配置`uglify`。

+   跟踪任何进一步的错误并进行更新。

让我们详细了解每个步骤，并探索命令行中到底发生了什么。这应该有助于您更好地理解该过程：

1.  我们需要做的第一件事是升级 Webpack 并安装`webpack-cli`。这是在命令行中完成的，如下所示：

```js
yarn add webpack
yarn add webpack-cli
```

1.  前面的示例显示了使用`yarn`来完成这个操作，并且还会进行版本检查。这也应该在`package.json`文件中可见：

```js
...
"webpack": "⁵.0.0",
"webpack-cli": "³.2.3",
...
```

1.  完成后，应该将相应的模式添加到`webpack.config.dev.js`和`webpack.config.prod.js`。参见以下`webpack.config.dev.js`文件：

```js
module.exports = {
mode: 'development',
```

与生产配置一样，我们在这里为每种模式都有两个配置文件。以下显示了`webpack.config.prod.js`文件的内容：

```js
module.exports = {
mode: 'production',
```

我们正在处理两个版本——旧版本（3）和新版本（4）。如果这是手动完成的，您可能首先要对原始版本进行**fork**。fork 一词指的是通常与此操作相关的图标，它代表一行从另一行分离出来，看起来像一个叉子。因此，fork 一词已经成为一个分支的意思。fork 检查器将自动检查每个版本的差异，以便作为操作的一部分进行更新。

1.  现在，回到命令行添加以下 fork 检查器：

```js
add fork-ts-checker-notifier-webpack-plugin
yarn add fork-ts-checker-notifier-webpack-plugin --dev
```

`package.json`文件中应该看到以下内容：

```js
...
"fork-ts-checker-notifier-webpack-plugin": "¹.0.0",
...
```

前面的代码块显示了 fork 检查器已经安装。

1.  现在，我们需要使用命令行更新`html-webpack-plugin`：

```js
yarn add html-webpack-plugin@next
```

`package.json`现在应该显示如下内容：

```js
"html-webpack-plugin": "⁴.0.0-beta.5",
```

现在，我们需要调整`webpack.config.dev.js`和`webpack.config.prod.js`文件中的插件顺序。

1.  您应该采取这些步骤来确保`HtmlWebpackPlugin`在**`InterpolateHtmlPlugin`**之前声明，并且`InterpolateHtmlPlugin`在下面的示例中被声明：

```js
plugins: [
 new HtmlWebpackPlugin({
   inject: true,
   template: paths.appHtml
 }),
 new InterpolateHtmlPlugin(HtmlWebpackPlugin, env.raw),
```

1.  还要确保在命令行中更新`ts-loader`、`url-loader`和`file-loader`：

```js
yarn add url-loader file-loader ts-loader
```

1.  `package.json`文件保存了关于使用的版本的信息，就像之前提到的加载器一样，并且应该如下所示：

```js
"file-loader": "¹.1.11",
"ts-loader": "4.0.0",
"url-loader": "0.6.2",
```

如果您正在使用**React**，那么您需要更新开发实用程序，如下所示：

```js
yarn add react-dev-utils
```

同样，`package.json`文件将保存所使用的 React 实用程序的版本信息：

```js
"react-dev-utils": "6.1.1",
```

`extract-text-webpack-plugin`应该被替换为**`mini-css-extract-plugin`。**

1.  请注意，应该完全删除`extract-text-webpack-plugin`，同时添加和配置`mini-css-extract-plugin`：

```js
yarn add mini-css-extract-plugin
```

1.  对于此示例，`package.json`文件中带有插件版本设置应该如下所示：

```js
"mini-css-extract-plugin": "⁰.5.0",
Config:
```

1.  完成所有这些后，我们应该看一下生产模式的配置。这是通过以下`webpack.config.prod.js`文件完成的：

```js
const MiniCssExtractPlugin = require("mini-css-extract-plugin");
plugins: [
 ...
 new MiniCssExtractPlugin({
   filename: "[name].css",
   chunkFilename: "[id].css"
 }),
 ...
 ],
 module: {
   rules: [
    {
     test: /\.css$/,
     use: [
     {
       loader: MiniCssExtractPlugin.loader,
       options: {
       // you can specify a publicPath here
       // by default it use publicPath in webpackOptions.output
       publicPath: '../'
     }
    },
    "css-loader"
   ]
 },
```

我们可以看到在不同版本之间的`webpack.config.prod.js`中有一些差异。前面的示例让你了解了在版本 4 中进行配置的格式。

1.  接下来，请确保使用命令行和`package.json`文件更新和重新配置`uglifyjs-webpack-plugin`：

```js
yarn add uglifyjs-webpack-plugin --dev
```

1.  为了谨慎起见，我们还将展示此处`uglify`插件的版本设置。使用`package.json`应用这些设置：

```js
"uglifyjs-webpack-plugin": "².1.2"
 Config:
```

1.  下一步，最后一步是使用`webpack.config.prod.js`配置生产模式：

```js
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
module.exports = {
  ...
  optimization: {
    minimizer: [new UglifyJsPlugin()],
 },
```

完成所有这些后，您应该完成更新过程。但是，您可能会遇到一个独特的弃用错误，这意味着您需要使用错误消息跟踪这些错误，然后根据需要更新任何进一步的 Webpack 插件。如果您正在使用自定义插件或加载器，情况将尤其如此。

# 总结

本章深入探讨了代码调试，并讨论了 HMR 和其他调试技术。您现在应该对可以用于增强调试过程的工具和实用程序有了牢固的掌握，包括使用`node nightly`进行代码检查。然后我们深入研究了 HMR，这是 Webpack 的一个显著和令人兴奋的特性。我们看到了如何对模块和样式表进行实时编辑，甚至涵盖了迁移问题。然后我们过渡到添加实用程序，这是任何升级的重要部分。从那里，我们带您完成了版本迁移，即从版本 3 迁移到版本 4，并介绍了相应的步骤。此外，我们还向您展示了如何从版本 4 迁移到版本 5。本节以一个漫长的教程结束，介绍了如何将命令行升级更新为对一些更棘手的元素进行手动更改。

您现在应该对自己的调试和升级技能充满信心，这将使您在下一章中站稳脚跟。在下一章中，我们将进行一些繁重的现场编码、定制和手动捆绑，这无疑会让您兴奋不已！

# 进一步阅读

本章涵盖了一些复杂问题，通过进一步阅读可以更好地理解。以下是一些主题以及在本章中提到的相关内容的查找位置：

+   调试优化退出

+   问题 6074—为`sideEffects`添加对更复杂选择器的支持

# 问题

现在，尝试一下与本章相关的以下问题。您将在本书的*评估*部分中找到答案：

1.  HMR 是什么意思？

1.  React Hot Loader 是做什么的？

1.  Webpack 通过哪个接口进行更新？

1.  Node v6.3.0+的哪个功能允许通过 Chrome DevTools 进行调试？

1.  从 Webpack 版本 3 迁移到版本 4 并使用自定义加载器转换`.json`文件时，您还必须改变什么？

1.  side effects 列表如何帮助开发？

1.  在生产模式中应该从哪里删除不推荐使用的插件？
