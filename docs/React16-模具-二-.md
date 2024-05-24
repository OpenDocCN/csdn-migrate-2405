# React16 模具（二）

> 原文：[`zh.annas-archive.org/md5/649B7A05B5FE7684E1D753EE428FF41C`](https://zh.annas-archive.org/md5/649B7A05B5FE7684E1D753EE428FF41C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：强制执行代码质量以提高可维护性

如果一个项目的代码是一致的且易于阅读，那不是很好吗？之所以通常情况下不是这样，是因为强制执行这种程度的代码质量是繁重的。当手动完成某事是一种负担时，您就引入了一个工具。

本章的重点是使用工具来确保您的 React 代码质量达到标准。以下是本章的学习内容：

+   安装和配置 ESLint

+   在 React 源代码上运行 ESLint

+   从 Airbnb 获取配置帮助

+   对 JSX 和 React 组件进行 Linting

+   将 ESLint 与您的代码编辑器集成

+   自定义 ESLint 错误和警告

+   使用 Prettier 自动格式化代码

# 安装和配置 ESLint

自动化 React 源代码质量的第一步是安装和配置用于自动化的工具—ESLint。当安装了 ESLint 时，它会在您的系统上安装一个`eslint`命令。与安装全局命令的其他软件包一样，最好将它们作为项目的一部分安装在本地，这样您就不必依赖系统上全局可用的命令。

要在项目中安装 ESLint，请运行以下`npm`命令：

```jsx
npm install eslint --save-dev
```

现在您已经安装了 ESLint，您可以创建一个新的 npm 脚本来运行 ESLint。将以下内容添加到您的`package.json`文件的`scripts`部分：

```jsx
"scripts": { 
  ... 
  "lint": "eslint" 
}, 
```

现在您有了一个可以在项目中运行的`eslint`命令。试一试吧：

```jsx
npm run lint
```

而不是对任何源文件进行 Linting，您应该在控制台中看到一个使用消息：

```jsx
eslint [options] file.js [file.js] [dir]

Basic configuration:
  -c, --config path::String      Use configuration from this file or shareable config
  --no-eslintrc                  Disable use of configuration from .eslintrc
  --env [String]                 Specify environments
  --ext [String]                 Specify JavaScript file extensions - default: .js
  --global [String]              Define global variables
  --parser String                Specify the parser to be used
  --parser-options Object        Specify parser options 
...
```

如您所见，您必须告诉`eslint`命令您想要进行 Lint 的文件或目录。为了保持简单，让我们假设我们所有的代码都在与`package.json`相同的目录中。您可以修改您的`package.json`文件如下，以便 ESLint 知道在哪里查找文件：

```jsx
"scripts": { 
  ... 
  "lint": "eslint ." 
}, 
```

您注意到在`eslint`后面添加了点(`.`)吗？这意味着在大多数系统上是当前目录。继续运行`npm run lint`。这一次，您将看到不同的输出，因为 ESLint 实际上正在尝试查找要进行 Lint 的源文件：

```jsx
Oops! Something went wrong! :(ESLint: 4.15.0.
ESLint couldn't find a configuration file. To set up a configuration file for this project, please run:
 eslint --init
```

好的，让我们按照它告诉我们的去做。我们将运行`npm run lint -- --init`来创建一个配置文件。当您这样做时，您将看到一系列选项供您选择：

```jsx
? How would you like to configure ESLint? 
› Answer questions about your style 
 Use a popular style guide 
 Inspect your JavaScript file(s) 
```

现在让我们选择第一个选项，并回答一些关于您计划编写的代码的基本问题。选择选项后，按下*Enter*键将带您到第一个问题：

```jsx
? Are you using ECMAScript 6 features? (y/N)  
```

是的，你是。

```jsx
? Are you using ES6 modules? (y/N)
```

是的，你是。

```jsx
? Where will your code run? (Press <space> to select, <a> to toggle all, <i> to inverse selection)
›(*) Browser
 ( ) Node
```

选择 `Browser`。

```jsx
? Do you use CommonJS? (y/N)  
```

不。

```jsx
? Do you use JSX? (y/N)  
```

不。我们稍后会介绍 JSX。

```jsx
? What style of indentation do you use? (Use arrow keys)
› Tabs 
  Spaces
```

在这里使用任何你喜欢的，因为我最终肯定会错。

```jsx
? What quotes do you use for strings? (Use arrow keys)
› Double 
  Single 
```

单个。你是什么，一个动物吗？

```jsx
? What line endings do you use? (Use arrow keys)
› Unix
  Windows
```

Unix 在这里是一个安全的选择。

```jsx
? Do you require semicolons? (Y/n)  
```

这是一个棘手的问题。在 JavaScript 源代码中分号不是必需的。有时它们可以帮助，而其他时候它们只是为了一些 JavaScript 解释器已经理解的东西而添加的语法。如果你不确定，要求使用分号；你总是可以稍后更改你的 ESLint 配置：

```jsx
? What format do you want your config file to be in? (Use arrow keys)
› JavaScript 
  YAML 
  JSON 
```

使用你最舒适阅读和编辑的任何东西。我将坚持使用 JavaScript 的默认选项：

```jsx
Successfully created .eslintrc.js file
```

万岁！让我们再试一次运行这个：

```jsx
npm run lint
```

这次没有输出。这意味着 ESLint 没有发现任何错误。部分原因是项目中还没有代码，但是现在你有了一个已知的工作起点。让我们快速看一下为你创建的 `.eslintrc.js` 文件：

```jsx
module.exports = { 
    "env": { 
        "browser": true, 
        "es6": true 
    }, 
    "extends": "eslint:recommended", 
    "parserOptions": { 
        "sourceType": "module"
```

```jsx
    }, 
    "rules": { 
        "indent": [ 
            "error", 
           4 
        ], 
        "linebreak-style": [ 
            "error", 
            "unix" 
        ], 
        "quotes": [ 
            "error", 
            "single" 
        ], 
        "semi": [ 
            "error", 
            "always" 
        ] 
    } 
}; 
```

既然你已经回答了创建这个文件所需的问题，你现在不需要改变任何东西。当你需要时，这就是要编辑的文件。当你只是学习 ESLint 时，像这样打出一个配置文件可能会让人望而却步。但是，当你决定你的代码质量标准需要调整时，ESLint 规则参考（[`eslint.org/docs/rules/`](https://eslint.org/docs/rules/)）是一个很好的资源。

作为为项目设置和配置 ESLint 的最后一步，让我们引入一些源代码进行 lint。如果还没有，创建一个 `index.js` 文件，并添加以下函数：

```jsx
export const myFunc = () => 'myFunc';
```

不要担心运行这个函数，linting 不像测试或类型检查那样。相反，linting 为开发人员提供了关于他们从代码质量角度做错了什么的易于忽视的提示。正确性与代码质量是不同的。这意味着你有许多可调整的选项与 ESLint，告诉它如何评估你的代码。

现在，回到你刚刚添加的函数。你可以通过再次运行 `npm run lint` 来验证这个函数是否正确。果然，根据你在 `.eslintrc.js` 中配置的规则，这个函数是好的。现在，尝试从函数中删除分号，使其看起来像这样：

```jsx
export const myFunc = () => 'myFunc' 
```

这次，你会从 ESLint 得到一个错误：

```jsx
index.js 
  1:37  error  Missing semicolon  semi 
Χ 1 problem (1 error, 0 warnings)
```

这是您需要的确切输出类型。它为您提供了源文件的名称，文件中错误/警告的位置，并描述了找到的实际问题。

让我们再试一次。请恢复您删除的分号。现在，删除 `export` 语句，使您的函数定义如下：

```jsx
const myFunc = () => 'myFunc'; 
```

当对此代码进行检查时，您会得到不同的错误：

```jsx
index.js 
  1:7  error  'myFunc' is assigned a value but never used  no-unused-vars Χ 1 problem (1 error, 0 warnings)
```

因为您删除了 `export` 关键字，所以模块只是一个分配给 `myFunc` 的函数。它从未被使用，ESLint 能够告诉您这一点。

# 建立在 Airbnb 标准的基础上

拥有大型 JavaScript 代码库的组织已经在代码质量工具上进行了大量投资。这包括在配置诸如 ESLint 之类的工具方面的投资。使用一组标准的配置值来强制执行代码质量的伟大之处在于，由于轻微的配置差异，开发人员之间不会有任何差异。

ESLint 允许您安装和使用 npm 包作为配置设置来使用和扩展。一个受欢迎的选择是 Airbnb 标准。让我们再次使用 ESLint `init` 工具来开始使用 Airbnb JavaScript 代码质量标准。首先，再次运行 `init` 工具：

```jsx
npm run lint -- --init
```

第一个问题问您如何配置 ESLint。您可以选择一个指南而不是回答问题：

```jsx
? How would you like to configure ESLint? 
  Answer questions about your style 
› Use a popular style guide 
  Inspect your JavaScript file(s) 
```

下一个问题让您选择要遵循的指南。您想要遵循 Airbnb 的指南：

```jsx
? Which style guide do you want to follow? 
  Google  
›  Airbnb 
  Standard 
```

现在，ESLint 将安装必要的 npm 包以使用 Airbnb 的 ESLint 配置设置：

```jsx
Checking peerDependencies of eslint-config-airbnb-base@latest 
Installing eslint-config-airbnb-base@latest, eslint-plugin-import@².7.0 

+ eslint-plugin-import@2.8.0 
+ eslint-config-airbnb-base@12.1.0 
```

让我们看看 ESLint 创建的 `.eslintrc.js` 文件是什么样子的：

```jsx
module.exports = { 
  "extends": "airbnb-base" 
}; 
```

正如您所看到的，现在这个文件非常简单，因为一切都由 `airbnb-base` npm 包处理。您的 `.eslintrc.js` 只是在扩展它。让我们看看这些 Airbnb 规则是如何起作用的。将以下代码添加到 `index.js` 中：

```jsx
const maybe = v => v ? v : 'default';

console.log(maybe('yes'));
// -> yes
console.log(maybe());
// -> default
```

`maybe()` 函数如果参数为真，则返回该参数；否则返回字符串 `default`。然后，使用字符串值和没有值来调用 `maybe()`。注释指示了这两个函数调用的输出。随时运行此代码以确保它按照广告中的方式工作。

在您这样做之后，让我们看看 Airbnb 对您的代码有何看法：

```jsx
npm run lint
```

这是输出：

```jsx
index.js 
  1:15  error    Arrow function used ambiguously with a conditional expression     no-confusing-arrow
```

```jsx
 1:24  error    Unnecessary use of conditional expression for default assignment  no-unneeded-ternary 
  3:1   warning  Unexpected console statement                                      no-console 
  5:1   warning  Unexpected console statement                                      no-console 
Χ 4 problems (2 errors, 2 warnings)
```

四个问题！哎呀。让我们逐个解决每个问题，看看能做些什么。第一个错误是`no-confusing-arrow`，它表示箭头函数与比较运算符模糊地使用了。您可以查看每个错误的具体内容（[`eslint.org/docs/rules/`](https://eslint.org/docs/rules/)），在那里您将找到详细的解释和示例。

接下来的错误`no-unneeded-ternary`与第一个错误密切相关。它指出我们可以使用比三元表达式更简单的表达式，这应该有助于提高代码的可读性。所以让我们试一试。`maybe()`函数应该返回参数或者如果参数为假的话返回一些默认值。除了三元运算符，让我们尝试使用逻辑或(||)：

```jsx
const maybe = (v = 'default') => v; 
```

这里的可读性稍有改善，明显减少了语法。关于这个微小改进本身更重要的是，每个在这个代码库上工作的开发人员都会做出相同的微小改进。让我们看看现在`npm run lint`会说些什么：

```jsx
index.js 
  6:1  warning  Unexpected console statement  no-console 
  8:1  warning  Unexpected console statement  no-console 
Χ 2 problems (0 errors, 2 warnings)
```

太棒了！您只剩下两个警告。但这些警告只是在抱怨您的`console.log()`调用。显然，Airbnb 的 ESLint 规则不喜欢这样做，但您喜欢。由于您只是通过扩展它们来使用 Airbnb 规则设置作为起点，您也可以关闭它们。在您的情况下，`no-console`规则没有任何作用，因为您显然依赖它。为此，编辑您的`.eslintrc.js`文件，使其如下所示：

```jsx
module.exports = { 
  "extends": "airbnb-base", 
  "rules": { 
    "no-console": 0 
  } 
}; 
```

在 ESLint 配置的`extends`部分之后，您可以添加一个`rules`部分，您可以在其中关闭由`airbnb-base`定义的特定规则。在这个例子中，将`no-console`设置为`0`告诉 ESLint 不应报告这些警告。让我们再次运行`npm run lint`，看看是否已经修复了所有问题。

果然，没有更多的错误要报告了！

# 向 ESLint 添加 React 插件

假设您想在尝试并喜欢了之后使用 Airbnb 的 ESLint 规则集。假设您还想对 React 组件代码进行 lint。在 ESLint `init`过程中，您已经回答了一个问题，该问题询问您的项目是否使用 React。这次，让我们回答“是”。所以，再次运行 ESLint `init`过程：

```jsx
npm run lint -- --init
```

再次，您想使用 Airbnb 的 lint 规则：

```jsx
? Which style guide do you want to follow? 
  Google 
›  Airbnb 
  Standard 
```

当它询问您是否使用 React 时，回答“是”：

```jsx
? Do you use React? (y/N) y
```

您会注意到安装了一些额外的包：

```jsx
+ eslint-plugin-react@7.5.1
+ eslint-plugin-jsx-a11y@6.0.3  
```

现在让我们编写一些 React 代码，以便我们可以对其进行 lint。将以下组件添加到`MyComponent.js`中：

```jsx
import React, { Component } from 'react'; 

class MyComponent extends Component { 
  render() { 
    return ( 
      <section> 
        <h1>My Component</h1> 
      </section> 
    );
```

```jsx
  } 
} 

export default MyComponent; 
```

这是组件的渲染方式：

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import MyComponent from './MyComponent'; 

const root = document.getElementById('root'); 

ReactDOM.render( 
  <MyComponent />, 
  root 
); 
```

您不需要担心在浏览器中运行此 React 应用程序；这只是为了确保 ESLint 能够解析 JSX 并对其进行 lint。现在让我们尝试运行 ESLint：

```jsx
npm run lint
```

在对源代码进行 lint 时，这里是生成的错误：

```jsx
index.js 
  5:14  error  'document' is not defined                      no-undef 
  8:3   error  JSX not allowed in files with extension '.js'  react/jsx-filename-extension 
  9:7   error  Missing trailing comma                         comma-dangle 

MyComponent.js 
  3:1  error  Component should be written as a pure function  react/prefer-stateless-function 
  6:7  error  JSX not allowed in files with extension '.js'   react/jsx-filename-extension 
```

您需要处理两个源文件中的错误。现在让我们逐个讨论这些错误。

来自`index.js`的第一个错误是`no-undef`，它指的是一个不存在的`document`标识符。问题是，您知道`document`是在浏览器环境中全局存在的标识符。ESLint 不知道这个全局标识符被定义了，所以我们必须在`.eslintrc.js`中告诉它这个值：

```jsx
module.exports = { 
  "extends": "airbnb",
```

```jsx
  "globals": {
    "document": true 
  } 
}; 
```

在 ESLint 配置的`globals`部分，您可以列出 ESLint 应该识别的全局标识符的名称。如果标识符实际上在引用它的源代码中是全局可用的，则值应为`true`。这样，ESLint 就知道不会抱怨在浏览器环境中识别为全局标识符的东西。

为特定环境中存在的标识符（如 Web 浏览器）添加全局标识符的问题在于它们有很多。您不希望维护这样一个列表，以便 ESLint 通过您的源代码。幸运的是，ESLint 对此有解决方案。您可以指定代码将在的环境，而不是指定`globals`：

```jsx
module.exports = { 
  "extends": "airbnb", 
  "env": { 
    "browser": true 
  } 
}; 
```

通过将`browser`环境指定为`true`，ESLint 知道所有浏览器全局变量，并且在代码中找到它们时不会抱怨。此外，您可以指定多个环境，因为通常会有在浏览器和 Node.js 中运行的代码。或者即使您不在不同环境之间共享代码，也可能希望对同时具有客户端和服务器代码的项目进行 lint。在任何一种情况下，这是多个 ESLint 环境的示例：

```jsx
module.exports = { 
  "extends": "airbnb", 
  "env": { 
    "browser": true, 
    "node": true 
  } 
}; 
```

要修复的下一个错误是`react/jsx-filename-extension`。这个规则来自于你初始化 ESLint 配置时安装的`eslint-plugin-react`包。该规则希望你使用不同的扩展名来命名包含 JSX 语法的文件。假设你不想麻烦这个（我不会责怪你，为几乎相同类型的文件内容维护两个文件扩展名太费劲了）。让我们暂时禁用这个规则。

这是更新后的 ESLint 配置：

```jsx
module.exports = {
  "extends": "airbnb", 
  "env": { 
    "browser": true, 
    "node": true 
  }, 
  "rules": { 
    "react/jsx-filename-extension": 0 
  } 
}; 
```

`react/jsx-filename-extension`规则被设置为`0`，在配置的`rules`部分中被忽略。继续运行`npm run lint`。现在只剩下两个错误了。

`comma-dangle`规则确实有自己的见解，但这是一个有趣的想法。让我们聚焦于触发这个错误的有问题的代码：

```jsx
ReactDOM.render( 
  <MyComponent />, 
  root 
); 
```

ESLint 抱怨在`root`参数后没有尾随逗号。添加尾随逗号的想法是：

+   后面添加项目更容易，因为逗号已经在那里

+   当你提交代码时，它会导致更清晰的差异，因为添加或删除项目只需要更改一行而不是两行

假设这是有道理的，你决定保留这个规则（我喜欢它），这是修复后的代码：

```jsx
ReactDOM.render( 
  <MyComponent />, 
  root, 
); 
```

现在让我们再次运行`npm run lint`。只剩下一个错误！这是另一个 React 特定的错误：`react/prefer-stateless-function`。让我们再看看触发这个错误的 React 组件：

```jsx
import React, { Component } from 'react'; 

class MyComponent extends Component {

  render() { 
    return (
      <section> 
        <h1>My Component</h1> 
      </section> 
    ); 
  } 
} 

export default MyComponent; 
```

ESLint 通过`eslint-plugin-react`的帮助，告诉你这个组件应该被实现为一个函数而不是一个类。它这么说是因为它能够检测到`MyComponent`没有任何状态，也没有任何生命周期方法。所以如果它被实现为一个函数，它：

+   不再依赖`Component`类

+   将是一个简单的函数，比类的语法要少得多

+   将明显地表明这个组件没有副作用

考虑到这些好处，让我们按照 ESLint 的建议，将`MyComponent`重构为一个纯函数：

```jsx
import React, { Component } from 'react';

const MyComponent = () => (
  <section>
    <h1>My Component</h1>
  </section>
);

export default MyComponent;
```

当你运行`npm run lint`时，你会得到：

```jsx
MyComponent.js 
  1:17  error  'Component' is defined but never used  no-unused-vars 
```

哎呀，在修复另一个错误的过程中，你引入了一个新的错误。没关系，这就是为什么要对代码进行检查，以找出容易忽略的问题。在这种情况下，是因为我们忘记了去掉`Component`导入，所以出现了`no-unused-vars`错误。这是修复后的版本：

```jsx
import React from 'react';
const MyComponent = () => ( 
  <section>
    <h1>My Component</h1> 
  </section> 
); 

export default MyComponent; 
```

然后你就完成了，不再有错误！借助`eslint-config-airbnb`和`eslint-plugin-react`的帮助，你能够生成任何其他 React 开发人员都能轻松阅读的代码，因为很可能他们正在使用完全相同的代码质量标准。

# 使用 ESLint 与 create-react-app

到目前为止，在本章中你所看到的一切，你都必须自己设置和配置。并不是说让 ESLint 运行起来特别困难，但`create-react-app`完全抽象了这一点。记住，`create-react-app`的理念是尽快开始编写组件代码，而不必考虑配置诸如 linters 之类的东西。

为了看到这一点的实际效果，让我们使用`create-react-app`创建一个新的应用程序：

```jsx
create-react-app my-new-app
```

然后，一旦创建，立即启动应用程序：

```jsx
npm start
```

现在让我们让 ESLint 抱怨一些事情。在你的编辑器中打开`App.js`，它应该看起来像这样：

```jsx
import React, { Component } from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 

class App extends Component { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header>
        <p className="App-intro"> 
          To get started, edit <code>src/App.js</code> and save to reload. 
        </p> 
      </div>
    ); 
  } 
} 

export default App; 
```

ESLint 认为这是可以的，所以让我们删除`Component`导入，这样`App.js`现在看起来像这样：

```jsx
import React from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 

class App extends Component { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header> 
        <p className="App-intro"> 
          To get started, edit <code>src/App.js</code> and save to reload. 
        </p> 
      </div> 
    ); 
  } 
} 

export default App; 
```

你的`App`类现在试图扩展`Component`，但`Component`并不存在。一旦你保存文件，ESLint 将被调用，因为它作为 Webpack 插件集成到开发服务器中。在开发服务器控制台中，你应该看到以下内容：

```jsx
Failed to compile.

./src/App.js
Line 5:  'Component' is not defined  no-undef  
```

正如预期的那样，ESLint 会为你检测到问题。将 ESLint 集成到开发服务器中的好处是你不必记得调用`npm run lint`命令。如果 ESLint 不通过，整个构建将失败。

你不仅会在开发服务器控制台中收到构建失败的通知，而且还会直接在浏览器中收到通知：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/3f406b4c-3879-49c6-a61c-e8ad026edb07.png)

这意味着即使你忘记查看服务器控制台，也很难错过替换整个 UI 的通知。如果你撤消了故意破坏 ESLint 的更改（重新添加`Component`导入），一旦你保存`App.js`，你的 UI 会再次显示出来。

# 在代码编辑器中使用 ESLint

如果你想要进一步对`create-react-app`的代码进行 linting，你可以这样做。如果你正在编写组件代码，你最不想做的事情就是不得不切换到控制台或浏览器窗口，只是为了查看你写的东西是否足够好。对于一些人来说，更好的开发体验是在他们的编辑器中看到 lint 错误发生。

让我们看看如何在 Atom 中实现这一点。首先，你需要安装`linter-eslint`插件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d459320f-f325-4d75-9d75-08006e6a1ce7.png)

现在当你在 Atom 中打开 JavaScript 源文件时，这个插件会为你进行 lint，并在行内显示错误和警告。唯一的挑战是`create-react-app`实际上并没有为你创建一个`.eslintrc.js`文件。这是因为`create-react-app`的性质是默认情况下隐藏所有配置。

然而，ESLint 仍然由`create-react-app`配置。这就是在启动开发服务器时对你的源代码进行 lint 的方式。问题在于你可能希望在编辑器 linter 中使用这个配置。`create-react-app`安装了一个名为`eslint-config-react-app`的包，其中包含开发服务器使用的 ESLint 配置。你可以在自己的项目中使用这个配置，这样你的编辑器 linter 就配置与浏览器或控制台中输出的内容相同。这非常重要，你最不希望的就是编辑器告诉你代码的一些问题，而你在浏览器中却看不到任何问题。

如果你在 Atom 中打开`App.js`，你不应该看到任何 lint 错误，因为：

+   没有任何

+   `linter-eslint` Atom 插件没有运行，因为它没有找到任何配置

当没有错误时，文件看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/5bc16047-7d07-42f8-8a6b-638eb78bfc22.png)

你所要做的就是添加扩展`eslint-config-react-app`配置的 ESLint 配置。在你的项目根目录中，创建以下`.eslintrc.js`文件：

```jsx
module.exports = { 
  "extends": "eslint-config-react-app" 
}; 
```

现在 Atom 的`linter-eslint`插件将尝试实时对你的开源文件进行 lint。此外，它将使用与你的`create-react-app`开发服务器完全相同的配置。让我们再试着删除`Component`导入。现在你的编辑器看起来有点不同：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/86c8361e-2d5b-4dec-aebe-2da5b875a01b.png)

正如你所看到的，`Component`标识符被用红色下划线标出，以便突出显示代码的这一部分。在你的源代码下面，有一个窗格显示了找到的每个 linter 错误的列表，以及有关每个错误的更多细节。如果你运行`npm start`，你会在开发服务器控制台和浏览器中看到完全相同的错误，因为 Atom 使用与`create-react-app`相同的 ESLint 配置。

现在让我们消除这个错误。转到以下代码行：

```jsx
import React from 'react';
```

将其改回：

```jsx
import React, { Component } from 'react'; 
```

在你的编辑器中不应该再显示任何 linter 错误。

# 使用 Prettier 自动化代码格式化

ESLint 可以用来改进代码的任何方面，包括格式。使用 ESLint 的问题在于它只告诉你它发现的格式问题。你仍然需要去修复它们。

这就是为什么 `create-react-app` 的 ESLint 配置没有指定任何代码格式规则。这就是 Prettier 这样的工具发挥作用的地方。它是一个针对你的 JavaScript 代码的有主见的代码格式化工具。它可以直接理解 JSX，因此非常适合格式化你的 React 组件。

`create-react-app` 用户指南中有一个完整的部分介绍了如何设置 Git 提交钩子，以在提交之前触发 Prettier 格式化任何代码：[`github.com/facebookincubator/create-react-app#user-guide`](https://github.com/facebookincubator/create-react-app#user-guide)。

我不会在这里重复这个指南，但基本思想是，设置好 Git 钩子，以便在提交任何 JavaScript 源代码时调用 Prettier 来确保一切都格式化得很好。只依赖 Git 提交钩子的缺点是，作为开发人员，你不一定在编写代码时看到格式化后的代码。

除了设置 Prettier 在每次提交时格式化 JavaScript 源代码之外，添加代码编辑器插件可以大大改善开发体验。再次，你可以安装适当的 Atom 包（或类似的东西；Atom 很受欢迎，所以我在这里使用它作为示例编辑器）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/de3701a4-2d78-41d9-bf86-3955c992be2b.png)

安装了 `prettier-atom` 包后，你可以使用 Atom 来格式化你的 React 代码。默认情况下，这个包使用快捷键 *Ctrl* + *Alt* + *F* 来调用 Prettier 格式化当前的源文件。另一个选项是在保存时启用格式化。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/74792524-4085-43ba-9221-f16b4ab2cea1.png)

现在，每次保存 JavaScript 源代码时，Prettier 都会对其进行格式化。让我们来测试一下。首先，打开 `App.js`，完全破坏格式，让它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/7ad2ee5c-1e86-4853-9397-92c2c206e72f.png)

恶心！让我们保存文件，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/29c76647-3a04-45ef-ba5a-05c2277c363b.png)

这样好多了。想象一下，如果你不得不手动修复那个混乱的代码。Prettier 可以让你的代码清晰，几乎不需要你费心思。

# 总结

本章重点介绍了使用工具来强制执行 React 项目的代码质量水平。您学习了第一个工具是 ESLint。您学会了如何安装和配置它。您很少需要手动配置 ESLint。您学会了如何使用 ESLint 初始化工具，该工具会引导您完成配置 ESLint 规则的各种选项。

接下来，您了解了不同的标准 ESLint 配置，可以在您的 React 应用程序中使用。Airbnb 是一个流行的标准，您可以在 ESLint 中使用，并且可以逐条自定义规则以适应您团队的特定风格。您还可以告诉 ESLint 初始化工具，您打算使用 React，并让它为您安装适当的软件包。

最后，您了解了`create-react-app`如何使用 ESLint。它使用一个 Webpack 插件在运行开发服务器时对您的代码进行 lint。您学会了`create-react-app`如何为此配置 ESLint，以及如何在代码编辑器中使用此配置。Prettier 是一个工具，它将自动格式化您的代码，这样您就不必花时间手动处理大量的 ESLint 样式警告。

在下一章中，您将学习如何使用 Storybook 在它们自己的环境中隔离 React 组件开发。


# 第七章：使用 Storybook 隔离组件

React 组件是较大用户界面的较小部分。自然而然，您希望与应用程序的其余部分一起开发 UI 组件。另一方面，如果您唯一的环境是在较大的 UI 内部，那么尝试组件更改可能会变得棘手。本章的重点是向您展示如何利用 Storybook 工具提供一个隔离的沙盒来开发 React 组件。您将学到：

+   隔离组件开发的重要性

+   安装 Storybook 并进行设置

+   使用故事开发组件

+   将组件引入应用程序

# 隔离组件开发的需求

在开发过程中隔离 React 组件可能会很困难。开发人员和他们正在制作的 React 组件所拥有的唯一上下文通常只有应用程序本身。在组件开发过程中很少会按计划进行。调试 React 组件的一部分是，嗯，与之互动。

我经常发现自己在应用程序代码中做一些奇怪的事情，以适应我们对组件进行临时更改时出现的问题。例如，我会更改容器元素的类型，看看这是否导致了我看到的布局问题；或者，我会更改组件内部的标记；或者，我会完全捏造一些组件使用的状态或属性。

重点是，在开发组件的过程中，您将想要进行一些随机实验。在您构建的应用程序中尝试这样做可能会很麻烦。这主要是因为您被迫接受组件周围的一切，当您只关心看看您的组件做了什么时，这可能会分散注意力。

有时，我最终会创建一个全新的页面，或者一个全新的应用程序，只是为了看看我的组件单独做了什么。这是一个痛苦的过程，其他人也有同样的感受，这就是为什么**Storybook**存在的原因。React 工具存在是为了为 React 开发人员自动化某些事情。使用 Storybook，您正在自动化一个沙盒环境供您使用。它还为您处理所有构建步骤，因此您只需为组件编写一个故事并查看结果。

最好的方式是将 Storybook 视为类似 JSFiddle（[`jsfiddle.net/`](https://jsfiddle.net/)）或 JSBin（[`jsbin.com/`](https://jsbin.com/)）这样的网站。它们让你可以在不设置和维护环境的情况下尝试小段代码。Storybook 就像 React 的 JSFiddle，作为你项目的一个组成部分存在。

# 安装和配置 Storybook

使用 Storybook 的第一步是安装全局命令行工具。它被安装为全局工具，因为它可以同时用于许多项目，并且可以用来引导新项目。让我们从这第一步开始：

```jsx
npm install @storybook/cli -g
```

安装完成后，你将拥有用于修改`package.json`依赖项和生成样板 Storybook 文件的命令行工具。假设你已经使用`create-react-app`创建了一个新应用程序。进入你的应用程序目录，并使用 Storybook 命令行工具将 Storybook 添加到你当前的项目中：

```jsx
getstorybook
```

当你运行`getstorybook`命令时，它会为你做很多事情。当你运行这个命令时，以下是你应该看到的输出：

```jsx
getstorybook - the simplest way to add a storybook to your project. 
![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4f10e203-ce18-4c2c-ae60-5c08079192da.jpg) Detecting project type. ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/86ac4257-00f3-4fcb-92c0-73bde8dd7af4.png)
![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4f10e203-ce18-4c2c-ae60-5c08079192da.jpg) Adding storybook support to your "Create React App" based project. ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/86ac4257-00f3-4fcb-92c0-73bde8dd7af4.png)![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4f10e203-ce18-4c2c-ae60-5c08079192da.jpg) Preparing to install dependencies. ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/86ac4257-00f3-4fcb-92c0-73bde8dd7af4.png)
```

它会在添加任何内容之前尝试弄清楚你的项目类型，因为不同类型的项目会有不同的组织要求。`getstorybook`会考虑到这一点。然后，它会安装依赖项，样板文件，并向你的`package.json`添加脚本：

```jsx
 ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4f10e203-ce18-4c2c-ae60-5c08079192da.jpg) Installing dependencies.
To run your storybook, type:
 npm run storybook 
```

输出告诉你如何在项目中运行 Storybook 服务器。此时，你的`package.json`的`scripts`部分应该如下所示：

```jsx
"scripts": { 
  "start": "react-scripts start", 
  "build": "react-scripts build", 
  "test": "react-scripts test --env=jsdom", 
  "eject": "react-scripts eject", 
  "storybook": "start-storybook -p 9009 -s public", 
  "build-storybook": "build-storybook -s public" 
} 
```

我们将在本章后面看一下`build-storybook`脚本；你会更经常使用`storybook`脚本。

接下来，让我们来看看`getstorybook`为你创建的样板文件。首先，你会注意到在项目的顶层目录中有一个新的`.storybook`目录：

```jsx
.storybook/
├── addons.js
└── config.js
```

添加的两个文件如下：

+   `addons.js`：这个文件导入了 Storybook 的插件模块。默认情况下，会使用 actions 和 links 插件，但如果不需要可以移除。

+   `config.js`：这个文件导入了这个项目的故事，并配置 Storybook 来使用它们。

你还会在你的`src`目录中找到一个名为`stories`的新目录：

```jsx
src/
├── App.css
├── App.js
├── App.test.js
├── index.css
├── index.js
├── logo.svg
├── registerServiceWorker.js
└── stories
    └── index.js
```

记得`getstorybook`是如何发现你正在使用`create-react-app`来开发你的项目的吗？这就是它知道要把`stories`目录放在`src`下的方式。这里有两个演示故事，可以帮助你入门：

```jsx
import React from 'react'; 

import { storiesOf } from '@storybook/react'; 
import { action } from '@storybook/addon-actions'; 
import { linkTo } from '@storybook/addon-links'; 

import { Button, Welcome } from '@storybook/react/demo'; 

storiesOf('Welcome', module).add('to Storybook', () => ( 
  <Welcome showApp={linkTo('Button')} /> 
)); 

storiesOf('Button', module) 
  .add('with text', () => ( 
    <Button onClick={action('clicked')}>Hello Button</Button> 
  )) 
  .add('with some emoji', () => ( 
    <Button onClick={action('clicked')}></Button> 
  )); 
```

现在先不要担心这个文件里发生了什么，我们会搞清楚的。这些默认故事将被你为组件想出的故事所替代。将这些默认故事放在那里也很有帮助，这样当你第一次启动 Storybook 服务器时，你就有东西可以看。现在让我们来做吧：

```jsx
npm run storybook
```

几秒钟后，你应该会看到控制台输出，告诉你服务器运行的位置，这样你就可以在浏览器中打开它：

```jsx
Storybook started on => http://localhost:9009/
```

当你在浏览器中查看 Storybook 应用程序时，你应该看到的是：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/53c9334f-ba6d-4f76-aed5-3a3962bb2bc7.png)

以下是你所看到的大致情况：

+   左窗格是你找到所有故事的地方。这是显示两个默认 Storybook 故事的地方。

+   主窗格是你将看到所选故事的渲染内容的地方。

+   底部操作窗格是你将看到触发的操作被记录的地方。

让我们尝试在左窗格中选择一个不同的故事：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/76b9a4a5-12c8-4fab-a347-83b36072774e.png)

一旦你在左窗格中更改故事选择，你就会在主窗格中看到渲染的组件输出。在这种情况下，它是一个基本的按钮。

# 使用故事开发组件

Storybook 的价值在于，你不必设置应用程序就可以开始开发组件。或者，如果你已经在开发中有一个应用程序，你也不必想办法将正在进行中的组件集成到你的应用程序中。Storybook 是一个可以进行实验的工具。通过使用插件，你可以在担心将其集成到应用程序之前测试组件的几乎任何方面。

# 尝试使用 props 进行实验

也许，开始在 Storybook 中开发组件最直接的方法是开始尝试不同的属性值。为此，你只需要创建组件的不同故事，每个故事都有不同的属性值。

首先，让我们来看看你正在开发的组件：

```jsx
import React from 'react'; 

const MyComponent = ({ title, content, titleStyle, contentStyle }) => ( 
  <section> 
    <heading> 
      <h2 style={titleStyle}>{title}</h2> 
    </heading> 
    <article style={contentStyle}>{content}</article> 
  </section> 
); 

export default MyComponent; 
```

这个组件并不复杂。它接受四个属性并呈现一些 HTML 标记。`title`和`content`属性的值都是简单的字符串。`titleStyle`和`contentStyle`属性是分配给相应 HTML 元素的`style`属性的对象。

让我们开始为这个组件编写故事。假设使用了与前一节相同的方法：

1.  `create-react-app`用于创建 React 应用程序结构并安装依赖项

1.  `getstorybook`用于检查当前项目并添加适当的样板和依赖项

您可以打开`src/stories/index.js`并开始使用`storiesOf()`函数：

```jsx
storiesOf('MyComponent Properties', module) 
```

这是启动 Storybook UI 时将出现在左窗格中的顶级主题。在此函数下方是您添加单独故事的位置。由于您目前对测试不同的属性值感兴趣，您添加的故事将用于反映不同的属性值：

```jsx
.add('No Props', () => <MyComponent />) 
```

这将在 Storybook 的左窗格中添加一个名为`No Props`的故事。当您点击它时，您将看到在没有任何属性的情况下`MyComponent`在主窗格中的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b0588569-8f37-48c7-ad1c-b19b8198d29f.png)

这里没有什么可看的，因为`title`和`content`属性都缺失。由于这两个值是唯一可见的呈现内容，所以没有内容可显示。让我们切换到下一个故事：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/191017c1-328b-4013-8204-76cbf478f95f.png)

这次，选择了"Just "title" story"，您可以看到不同的 React 组件输出呈现。正如故事标题所示，只有`title`属性被传递给了`MyComponent`。以下是此故事的代码：

```jsx
.add('Just "title"', () => <MyComponent title="The Title" />) 
```

下一个故事只传递了`content`属性。以下是结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/888a25e6-b1eb-47ea-be79-7e19bf06f86d.png)

以下是仅传递`content`属性的代码：

```jsx
.add('Just "Content"', () => <MyComponent content="The Content" />) 
```

下一个故事将`title`和`content`属性都传递给`MyComponent`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d88b2ede-3ba4-4168-95f5-7544d7e6b640.png)

以下是在故事中呈现这两个属性的代码：

```jsx
.add('Both "title" and "content"', () => ( 
  <MyComponent title="The Title" content="The Content" /> 
)) 
```

此时，您的组件有三个故事，并且它们已经被证明是有用的。例如，您已经看到了`MyComponent`在没有内容或没有标题时的外观。根据结果，您可能决定将这两个属性都设为必填，或者提供默认值。

接下来让我们移动到样式属性。首先，您将只传递`titleStyle`属性，就像这样：

```jsx
.add('Just "titleStyle"', () => ( 
  <MyComponent 
    title="The Title" 
    content="The Content" 
    titleStyle={{ fontWeight: 'normal' }} 
  /> 
)) 
```

请注意，您还传递了`title`和`content`属性。这样，您就可以看到样式实际上如何影响`MyComponent`渲染的内容。这是结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/f36bbc51-e0c7-4de7-bc74-e42d4623d055.png)

接下来，您将只传递`contentStyle`属性：

```jsx
.add('Just "contentStyle"', () => (
  <MyComponent 
    title="The Title" 
    content="The Content" 
    contentStyle={{ fontFamily: 'arial', fontSize: '1.2em' }} 
  /> 
)) 
```

这是它的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/417a9c5e-ff34-482b-9407-650144cb4aa5.png)

最后，让我们将每个可能的属性传递给`MyComponent`：

```jsx
.add('Both "titleStyle" and "contentStyle"', () => ( 
  <MyComponent 
    title="The Title" 
    content="The Content"
```

```jsx
    titleStyle={{ fontWeight: 'normal' }} 
    contentStyle={{ fontFamily: 'arial', fontSize: '1.2em' }} 
  /> 
)); 
```

这是`MyComponent`传递给它的每个属性的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/ad8de25f-37c4-4154-bd79-54209d0f9d21.png)

您刚刚为一个简单的组件创建了七个故事。使用 Storybook 开发服务器和 Storybook 用户界面，很容易在您为组件创建的不同故事之间切换，以便您可以轻松地看到它们之间的差异。这对于只处理属性的功能组件特别有效，就像您刚刚看到的那样。

这是您刚刚实现的所有故事，这样您就可以看到它们一起是什么样子的：

```jsx
import React from 'react'; 
import { storiesOf } from '@storybook/react'; 
import MyComponent from '../MyComponent'; 

storiesOf('MyComponent Properties', module) 
  .add('No Props', () => <MyComponent />) 
  .add('Just "title"', () => <MyComponent title="The Title" />) 
  .add('Just "Content"', () => <MyComponent content="The Content" />) 
  .add('Both "title" and "content"', () => ( 
    <MyComponent title="The Title" content="The Content" /> 
  )) 
  .add('Just "titleStyle"', () => ( 
    <MyComponent 
      title="The Title" 
      content="The Content" 
      titleStyle={{ fontWeight: 'normal' }} 
    /> 
  )) 
  .add('Just "contentStyle"', () => ( 
    <MyComponent 
      title="The Title" 
      content="The Content" 
      contentStyle={{ fontFamily: 'arial', fontSize: '1.2em' }} 
    /> 
  )) 
  .add('Both "titleStyle" and "contentStyle"', () => ( 
    <MyComponent 
      title="The Title" 
      content="The Content" 
      titleStyle={{ fontWeight: 'normal' }} 
      contentStyle={{ fontFamily: 'arial', fontSize: '1.2em' }} 
    /> 
  )); 
```

为您的组件添加每个故事都有不同的属性配置的好处是，这就像为您的组件拍摄静态快照。然后，一旦您为组件有了几个故事，您可以在这些快照之间切换。另一方面，您可能还没有准备好以这种方式开始实现几个故事。如果您只是想玩弄属性值，有一个名为**Knobs**的 Storybook 插件。

旋钮插件允许您通过 Storybook UI 中的表单控件玩转 React 组件属性值。现在让我们试用一下这个插件。第一步是在您的项目中安装它：

```jsx
npm install @storybook/addon-knobs --save-dev
```

然后，您必须告诉您的 Storybook 配置，您想要使用这个插件。将以下行添加到`.storybook/addons.js`：

```jsx
import '@storybook/addon-knobs/register'; 
```

现在，您可以将`withKnobs`装饰器导入到您的`stories/index.js`文件中，该装饰器用于告诉 Storybook 接下来的故事将使用控件来玩转属性值。您还需要导入各种类型的旋钮控件。这些都是简单的函数，当 Storybook UI 中的值发生变化时，它们将值传递给您的组件。

作为示例，让我们复制刚刚为`MyComponent`实现的相同故事情节。这一次，不再构建一堆静态故事，每个故事都设置特定的属性值，而是只添加一个使用 Knobs 附加组件来控制属性值的故事。以下是需要添加的导入内容：

```jsx
import { withKnobs, text, object } from '@storybook/addon-knobs/react';
```

以下是故事的新上下文，以及一个使用旋钮控件来设置和更改 React 组件属性值的默认故事：

```jsx
storiesOf('MyComponent Prop Knobs', module) 
  .addDecorator(withKnobs) 
  .add('default', () => ( 
    <MyComponent 
      title={text('Title', 'The Title')} 
      content={text('Content', 'The Content')} 
      titleStyle={object('Title Style', { fontWeight: 'normal' })} 
      contentStyle={object('Content Style', { 
        fontFamily: 'arial', 
        fontSize: '1.2em' 
      })} 
    />
  )); 
```

从 Knobs 附加组件中导入的两个函数`text()`和`object()`用于设置旋钮控件的标签和默认值。例如，`title`使用`text()`函数并带有默认字符串值，而`contentStyle`使用`object()`函数并带有默认样式对象。

在 Storybook 用户界面中的效果如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0e07dc05-62de-4056-ad26-dc3a635e7820.png)

如果你看底部窗格，你会看到一个 KNOBS 标签，旁边是一个 ACTION LOGGER 标签。根据你用来声明故事的 Knobs 附加组件中的函数，这些表单控件被创建。现在你可以继续玩弄组件属性值，并观察呈现的内容实时变化：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b06e39bd-adf6-4806-beda-87b2cbce7cc6.png)

如果你在尝试旋钮字段时找到了喜欢的属性值，你可以将这些值硬编码到一个故事中。这就像是将一个组件配置标记为有效，以便以后可以返回到它。

# 尝试使用 actions

让我们将注意力转移到另一个附加组件——Actions。这个附加组件在你的 Storybook 中默认启用。Actions 的理念是，一旦你选择了一个故事，你就可以与主窗格中呈现的页面元素进行交互。Actions 为你提供了一种记录用户在 Storybook UI 中交互的机制。此外，Actions 还可以作为一个通用工具，帮助你监视数据在组件中的流动。

让我们从一个简单的按钮组件开始：

```jsx
import React from 'react'; 

const MyButton = ({ onClick }) => ( 
  <button onClick={onClick}>My Button</button> 
); 

export default MyButton; 
```

`MyButton`组件

渲染一个`<button>`元素并为其分配一个`onClick`事件处理程序。实际上，处理程序是由`MyComponent`定义的；它作为一个 prop 传递进来。因此，让我们为这个组件创建一个故事，并传递一个`onClick`处理程序函数：

```jsx
import React from 'react'; 
import { storiesOf } from '@storybook/react'; 
import { action } from '@storybook/addon-actions'; 
import MyButton from '../MyButton'; 

storiesOf('MyButton', module).add('clicks', () => ( 
  <MyButton onClick={action('my component clicked')} /> 
)); 
```

你看到了从`@storybook/addon-actions`导入的`action()`函数吗？这是一个高阶函数——一个返回另一个函数的函数。当你调用`action('my component clicked')`时，你会得到一个新的函数作为返回。这个新函数的行为有点像`console.log()`，你可以给它分配一个标签并记录任意值。不同之处在于，Storybook `action()` 插件函数创建的函数的输出会直接在 Storybook UI 的动作面板中呈现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/15be61dc-fc60-4a15-b122-47298b1d7f2a.png)

像往常一样，`<button>`元素被渲染在主面板中。你在动作面板中看到的内容是点击按钮三次的结果。每次点击的输出都是完全相同的，所以输出都被分组在你分配给处理函数的`my component clicked`标签下。

在上面的例子中，`action()`创建的事件处理函数对于作为你传递给组件的实际事件处理函数的替代是有用的。其他时候，你实际上需要事件处理行为来运行。例如，你有一个维护自己状态的受控表单字段，并且你想看看状态改变时会发生什么。

对于这样的情况，我发现最简单和最有效的方法是添加事件处理程序属性，即使你没有用它们做其他事情。让我们来看一个例子：

```jsx
import React, { Component } from 'react'; 

class MyRangeInput extends Component { 
  static defaultProps = { 
    onChange() {}, 
    onRender() {} 
  }; 

  state = { value: 25 }; 

  onChange = ({ target: { value } }) => { 
    this.setState({ value }); 
    this.props.onChange(value); 
  }; 

  render() { 
    const { value } = this.state; 
    this.props.onRender(value); 
    return ( 
      <input 
        type="range" 
        min="1" 
        max="100" 
        value={value} 
        onChange={this.onChange} 
      /> 
    ); 
  } 
}
export default MyRangeInput; 
```

让我们首先看一下这个组件的`defaultProps`。默认情况下，这个组件有两个`onChange`和`onRender`的默认处理函数，它们什么也不做，所以如果它们没有设置，仍然可以被调用而不会发生任何事情。正如你可能已经猜到的，现在我们可以将`action()`处理程序传递给`MyRangeInput`组件。让我们试一试。现在你的`stories/index.js`看起来是这样的：

```jsx
import React from 'react'; 
import { storiesOf } from '@storybook/react'; 
import { action } from '@storybook/addon-actions'; 
import MyButton from '../MyButton'; 
import MyRangeInput from '../MyRangeInput'; 

storiesOf('MyButton', module).add('clicks', () => ( 
  <MyButton onClick={action('my component clicked')} /> 
)); 

storiesOf('MyRangeInput', module).add('slides', () => ( 
  <MyRangeInput 
    onChange={action('range input changed')} 
    onRender={action('range input rendered')} 
  /> 
)); 
```

现在当你在 Storybook UI 中查看这个故事时，你应该会看到在滑动范围输入滑块时记录了很多动作。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/7c18980a-87db-4227-a3b5-76ae7b9e307f.png)

当滑块移动时，你可以看到传递给组件的两个事件处理函数在组件渲染生命周期的不同阶段记录了值。最近的操作被记录在面板顶部，不像浏览器开发工具会在底部记录最近的值。

让我们再次回顾一下`MyRangeInput`代码。滑块移动时调用的第一个函数是更改处理程序：

```jsx
onChange = ({ target: { value } }) => { 
  this.setState({ value }); 
  this.props.onChange(value); 
}; 
```

这个`onChange()`方法是`MyRangeInput`内部的。它是必需的，因为它渲染的`<input>`元素使用组件状态作为唯一的真相来源。在 React 术语中，这些被称为受控组件。首先，它使用事件参数的`target.value`属性设置值的状态。然后，它调用`this.props.onChange()`，将相同的值传递给它。这就是您可以在 Storybook UI 中看到事件值的方式。

请注意，这不是记录组件的更新状态的正确位置。当您调用`setState()`时，您必须假设您在函数中已经处理完状态，因为它并不总是同步更新。调用`setState()`只安排了状态更新和随后的重新渲染组件。

这里有一个可能会引起问题的例子。假设您不是记录事件参数中的值，而是在设置后记录值状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/64116467-b4fd-4379-a34d-158e29be003e.png)

现在出现了一点问题。`onChange`处理程序记录了旧状态，而`onRender`处理程序记录了更新后的状态。如果您试图追踪事件值到呈现的输出，这种记录输出会非常令人困惑-事情不会对齐！永远不要在调用`setState()`后记录状态值。

如果调用空操作函数的想法让您感到不舒服，那么在 Storybook 中显示操作的这种方法可能不适合您。另一方面，您可能会发现，无需在组件内部编写大量调试代码，就可以在组件的生命周期的任何时刻记录基本上任何内容的实用程序。对于这种情况，操作是一种方法。

# 链接故事在一起

链接故事书附加组件允许您以与链接常规网页相同的方式将故事链接在一起。故事书有一个导航窗格，允许您从一个故事切换到另一个故事。这就像一个目录一样有用。但是当您在网上阅读内容时，通常会在一个段落中找到几个链接。想象一下，如果在网上移动的唯一方法是查看每个文档中的目录中的链接，那将是痛苦的。

在网页内容中嵌入链接有价值的原因，同样在 Storybook 输出中嵌入链接也是有价值的：它们提供了上下文。让我们看一个链接实际应用的例子。与 Actions 一样，当您在项目中运行`getstorybook`命令时，链接插件默认启用。这是您将为其编写故事的组件：

```jsx
import React from 'react'; 

const MyComponent = ({ headingText, children }) => ( 
  <section> 
    <header> 
      <h1>{headingText}</h1> 
    </header> 
    <article>{children}</article> 
  </section> 
); 

MyComponent.defaultProps = { 
  headingText: 'Heading Text' 
}; 

export default MyComponent;
```

这个组件接受`headingText`和`children`属性。现在让我们编写一些相互关联的 Storybook 故事。以下是三个故事，它们在输出窗格中都相互关联：

```jsx
import React from 'react'; 
import { storiesOf } from '@storybook/react'; 
import { linkTo } from '@storybook/addon-links'; 
import LinkTo from '@storybook/addon-links/react'; 
import MyComponent from '../MyComponent'; 

storiesOf('MyComponent', module) 
  .add('default', () => ( 
    <section> 
      <MyComponent /> 
      <p> 
        This is the default. You can also change the{' '} 
        <LinkTo story="heading text">heading text</LinkTo>. 
      </p> 
    </section> 
  )) 
  .add('heading text', () => ( 
    <section> 
      <MyComponent headingText="Changed Heading!" /> 
      <p> 
        This time, a custom <code>headingText</code> prop 
        changes the heading text. You can also pass{' '} 
        <LinkTo story="children">child elements</LinkTo> to{' '} 
        <code>MyComponent</code>. 
      </p> 
      <button onClick={linkTo('default')}>Default</button> 
    </section> 
  )) 
  .add('children', () => ( 
    <section> 
      <MyComponent> 
        <strong>Child Element</strong> 
      </MyComponent> 
      <p> 
        Passing a child component. You can also change the{' '} 
        <LinkTo story="headingText">heading text</LinkTo> of{' '} 
        <code>MyComponent</code>. 
      </p> 
      <button onClick={linkTo('default')}>Default</button> 
    </section> 
  )); 
```

让我们逐个讲解这些故事，这样您就可以看到它们是如何相互关联的。首先是默认故事：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/f5870cd4-8d7c-4af9-89b6-f2db070f02a9.png)

您可以看到`MyComponent`的渲染内容，其中只包含标题文本，因为您没有传递任何子元素。此外，这只是默认的标题文本，因为在组件下方呈现的内容解释了这一点。这个内容方便地链接到一个呈现不同标题文本的故事：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/c749e9bb-4030-467f-a6b5-3a2e774214eb.png)

再次，您可以看到使用自定义`headingText` prop 值呈现的组件，并在组件下方有一个链接到另一个故事的注释。在这种情况下，链接将用户带到一个将子元素传递给`MyComponent`的故事：

```jsx
<LinkTo story="children">child elements</LinkTo>
```

还有一个按钮，它使用`linkTo()`函数构建一个回调函数，该函数将用户带到链接的故事，而不是渲染链接的`<LinkTo>`组件：

```jsx
<button onClick={linkTo('default')}>Default</button>
```

这两种方法都需要一个 kind 参数，但在这里被省略了，因为我们是从`MyComponent` kind 内部进行链接。像这样链接故事的能力使您更接近将 Storybook 作为记录 React 组件的工具。

# 故事作为文档

Storybook 不仅仅是一个方便的地方，可以在开发过程中隔离您的组件。通过插件，它也是一个有效的记录组件的工具。随着应用程序的增长，拥有类似 Storybook 这样的工具变得更加具有吸引力。其他开发人员可能需要使用您创建的组件。如果他们可以查看 Storybook 故事来了解组件的各种用法，那不是很好吗？

这一章我们将看一下的最后一个插件叫做 Info。它以一个漂亮的格式提供关于组件的使用信息，除了标准的渲染组件输出之外。

让我们创建一些我们想要记录的组件。与其像本章节一直以来那样在`stories/index.js`中编写每个故事，不如把你的故事分开成更易消化的内容：

+   `stories/MyButton.story.js`

+   `stories/MyList.story.js`

你即将要实现的两个组件的故事将分别在它们自己的模块中，这样以后维护起来会更容易一些。为了支持这种新的文件布局，你还需要在`.storybook/config.js`中做一些改变。在这里，你需要分别引入你的两个故事模块：

```jsx
import { configure } from '@storybook/react'; 

function loadStories() { 
  require('../src/stories/MyButton.story'); 
  require('../src/stories/MyList.story'); 
}
configure(loadStories, module); 
```

现在让我们来看看这些组件。首先是`MyButton`：

```jsx
import React from 'react'; 
import PropTypes from 'prop-types'; 

const MyButton = ({ onClick }) => ( 
  <button onClick={onClick}>My Button</button> 
); 

MyButton.propATypes = { 
  onClick: PropTypes.func 
}; 

export default MyButton; 
```

你可以看到`MyButton`定义了一个`propTypes`属性；很快你就会明白为什么这对于 Info Storybook 插件很重要。接下来，让我们看看`MyList`组件：

```jsx
import React from 'react'; 
import PropTypes from 'prop-types'; 

const Empty = ({ items, children }) => 
  items.length === 0 ? children : null; 

const MyList = ({ items }) => ( 
  <section> 
    <Empty items={items}>No items found</Empty> 
    <ul>{items.map((v, i) => <li key={i}>{v}</li>)}</ul> 
  </section> 
); 

MyList.propTypes = { 
  items: PropTypes.array 
}; 

MyList.defaultProps = { 
  items: [] 
}; 
export default MyList; 
```

这个组件还定义了一个`propTypes`属性。它也定义了一个`defaultProps`属性，这样当`items`属性没有提供时，默认情况下它是一个空数组，这样调用`map()`仍然有效。

现在你已经准备好为这两个组件编写故事了。记住你还希望这些故事作为组件的主要文档来源，你将使用 Storybook 的 Info 插件为任何给定的故事提供更多的使用信息。让我们从`MyButton.story.js`开始：

```jsx
import React from 'react'; 
import { storiesOf } from '@storybook/react'; 
import { withInfo } from '@storybook/addon-info'; 
import { action } from '@storybook/addon-actions'; 
import MyButton from '../MyButton'; 

storiesOf('MyButton', module) 
  .add( 
    'basic usage', 
    withInfo(' 
      Without passing any properties 
    ')(() => <MyButton />) 
  ) 
  .add( 
    'click handler', 
    withInfo(' 
      Passing an event handler function that's called when 
      the button is clicked 
    ')(() => <MyButton onClick={action('button clicked')} />) 
  ); 
```

在这里，你使用两个故事来记录`MyButton`，每个故事展示了组件的不同使用方式。第一个故事展示了基本用法，第二个故事展示了如何传递一个点击处理程序属性。这些故事的新添加是调用`withInfo()`。这个函数来自 Info Storybook 插件，你可以传递一些文本（支持 markdown），更详细地说明故事。换句话说，这是你记录组件特定用法的地方。

现在让我们先看看`MyList.story.js`，然后再看看 Info 插件在 Storybook UI 中的输出是什么样子的：

```jsx
import React from 'react'; 
import { storiesOf } from '@storybook/react'; 
import { withInfo } from '@storybook/addon-info'; 
import MyList from '../MyList'; 

storiesOf('MyList', module) 
  .add( 
    'basic usage', 
    withInfo(' 
      Without passing any properties
    ')(() => <MyList />) 
  ) 
  .add( 
    'passing an array of items', 
    withInfo(' 
      Passing an array to the items property 
    ')(() => <MyList items={['first', 'second', 'third']} />) 
  ); 
```

这看起来很像为`MyButton`定义的故事——不同的文档和组件，相同的整体结构和方法。

让我们来看看`MyButton`的默认使用故事：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/173851a2-9514-4873-95b8-f97a22cb9643.png)

如预期的那样，按钮会在输出窗格中呈现，以便用户可以看到他们正在使用的内容。在输出窗格的右上角，有一个信息按钮。当您点击它时，您会看到通过在故事中调用`withInfo()`提供的所有额外信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/2c317cd2-ae23-4c2a-9426-5ac0f3ec2975.png)

这会显示有关故事和您正在记录的组件的各种信息。从上到下，这是它显示的内容：

+   组件名称

+   故事名称

+   用法文档（作为`withInfo()`的参数提供）

+   用于呈现组件的源

+   组件可用的属性（从`propTypes`中读取）

Info 插件的好处在于它显示了用于呈现用户正在查看的输出的源，并且如果您将其提供为属性类型，则显示可用属性。这意味着试图理解和使用您的组件的人可以在您作为组件作者不费吹灰之力的情况下获得他们所需的信息。

让我们看看当`MyList`组件传递一个项目数组时的情况：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/2395c76a-2243-4bf8-8060-29eb28788f9a.png)

它呈现了通过属性获取的项目列表。现在让我们看看这个故事的信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/8d69e330-f9e9-440c-a697-7b86d579b607.png)

通过查看有关此故事的信息，您可以一目了然地看到此组件接受的属性、它们的默认值以及用于生成示例的代码，所有这些都在一个地方。我还喜欢信息窗格默认情况下是隐藏的这一事实，这意味着您可以浏览故事并寻找所需的最终结果，然后再担心细节。

# 构建静态 Storybook 应用程序

如果您正在构建组件库，并希望将其作为开源项目或与组织内的各个团队共享的内容，您可以使用 Storybook 作为记录如何使用您的组件的工具。也就是说，您可能不希望运行 Storybook 服务器，或者只想托管 Storybook 文档。

在任何一种情况下，您都需要组件库的故事的静态构建。当您运行`getstorybook`命令时，Storybook 会为您提供此实用程序。

让我们继续使用前一节的示例，您在其中使用 Storybook 来记录两个组件的使用场景。要构建您的静态 Storybook 文档，您只需在项目目录中运行以下命令：

```jsx
npm run build-storybook
```

你应该看到类似以下的输出：

```jsx
info @storybook/react v3.3.13
info 
info => Loading custom addons config.
info => Using default webpack setup based on "Create React App".
info => Copying static files from: public
info Building storybook ...  
```

构建完成后，您将在项目文件夹中看到一个新的`storybook-static`目录。在其中，您将看到几个文件，包括由 Webpack 创建的静态 JavaScript 捆绑包和一个`index.html`文件，您可以从任何 Web 服务器提供，或者直接在 Web 浏览器中打开。

# 总结

本章是一个名为 Storybook 的工具的重点。Storybook 为 React 开发人员提供了一个沙盒环境，使他们可以轻松地独立开发 React 组件。当您唯一的环境是您正在工作的应用程序时，这可能会很困难。Storybook 提供了一定程度的开发隔离。

首先，您学会了如何安装全局 Storybook 命令行实用程序，以及如何使用此实用程序在您的`create-react-app`项目中设置 Storybook。接下来，您学会了如何编写展示组件不同视角的故事。

然后，您了解到 Storybook 功能的很大一部分来自于插件。您了解到 Actions 可以帮助记录日志，链接提供了超出默认范围的导航机制。您还学会了如何使用 Storybook 为 React 组件编写文档。我们在本章结束时看了一下构建静态 Storybook 内容。

在下一章中，您将探索 Web 浏览器中可用的 React 工具。


# 第八章：在浏览器中调试组件

如果您正在开发 React Web 应用程序，您需要基于浏览器的工具来帮助您从 React 开发人员的角度查看页面上发生了什么。当今的 Web 浏览器默认安装了令人惊叹的开发人员工具。如果您进行任何类型的 Web 开发，这些工具是必不可少的，因为它们公开了 DOM、样式、性能、网络请求等方面的真实情况。

使用 React，您仍然需要所有这些工具，但您需要的不仅仅是这些。React 的核心原则是在 JavaScript 组件中使用声明性标记。如果这种抽象在开发人员为其他所有事情依赖的 Web 浏览器工具中不存在，生活会比必要的更加困难。

在本章中，您将学到：

+   安装 React Developer Tools 浏览器插件

+   定位和选择 React 组件

+   操作组件的 props 和 state

+   分析组件性能

# 安装 React Developer Tools 插件

开始使用 React 工具的第一步是安装 React Developer Tools 浏览器扩展。在本章的示例中，我将使用 Chrome，因为这是一个流行的选择。React Developer Tools 也可以作为 Firefox 的扩展使用（[`addons.mozilla.org/en-US/firefox/addon/react-devtools/`](https://addons.mozilla.org/en-US/firefox/addon/react-devtools/)）。

要在 Chrome 中安装扩展，请访问[`chrome.google.com/webstore/category/extensions`](https://chrome.google.com/webstore/category/extensions)并搜索`react developer tools`： 

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/f09d7cd6-acf2-4485-aca6-fb03a882cdbc.png)

第一个结果应该是您想要的扩展。点击“添加到 Chrome”按钮进行安装：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0f971519-8b9b-45f2-bd83-272180ee40c2.png)

Chrome 可能会警告您，它可以更改您访问的网站上的数据。别担心，该扩展仅在您访问 React 应用程序时才会激活：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/86b0a040-1848-4226-80bf-bbddd1756d1b.png)

点击“添加扩展”按钮后，扩展将被标记为已安装：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4238f215-8429-4760-834c-d10920df4224.png)

您已经准备好了！安装并启用 React Developer Tools Chrome 扩展后，您就可以开始检查页面上的 React 组件，就像您检查常规 DOM 元素一样。

# 在 React Developer Tools 中使用 React 元素

安装了 Chrome 中的 React 开发者工具后，你会在浏览器地址栏右侧看到一个按钮。我的按钮是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/cb811ae0-6b77-4acd-a83a-cf6576de8c47.png)

我这里有几个浏览器扩展的按钮。你可以看到最右边的是 React 开发者工具按钮，上面有 React 的标志。当按钮变灰时，意味着当前页面没有运行 React 应用。试着在其他页面点击一下这个按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/06aecb5f-f488-491a-9e82-e955b70ae8fe.png)

现在让我们使用`create-react-app`来创建一个新的应用程序，就像你在整本书中一直在做的那样：

```jsx
create-react-app finding-and-selecting-components
```

现在启动开发服务器：

```jsx
npm start
```

这应该会直接将你带到浏览器页面，你的 React 应用程序已经加载到一个新的标签页中。现在 React 开发者工具按钮应该看起来不一样了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/2ffa9251-6af2-41c0-8aad-0490faaccb6f.png)

就是这样。因为你在运行 React 应用的页面上，React 开发者工具按钮会变亮，告诉你它已经可用。现在试着点击一下它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/258cf495-5c39-4494-b6e6-51149bdafc05.png)

太棒了！React 开发者工具可以检测到这是 React 库的开发版本。如果你不小心将 React 的开发版本部署到生产环境中，这可能会派上用场。诚然，如今使用诸如`create-react-app`之类的工具构建生产版本是更加困难的，因为你已经具备了构建生产版本的工具。

好的，现在你已经安装了 React 浏览器工具，除了检测应用程序使用的 React 构建类型，它还能为你做些什么呢？让我们在 Chrome 中打开开发者工具面板看看：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/c1240c93-ff99-4812-ae3f-e92b0f059b2d.png)

你可以看到开发者工具面板中通常的部分：元素、控制台等等。但是没有关于 React 的内容？我把开发者工具面板停靠在了浏览器窗口的右侧，所以你看不到每个部分。如果你看到的也是一样的情况，你只需要点击性能旁边的箭头按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a19e461d-bb35-4dd2-b858-0e2f5c6bf504.png)

从菜单中选择 React，你将进入开发者工具面板的 React 部分。加载完成后，你应该会看到根 React 组件显示出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/4556b196-8ec0-4819-8939-18845b62d6f6.png)

如果你在任何浏览器中使用过 DOM 检查工具，这个界面应该会让你感到熟悉。在左侧的主要部分，你有你的 React 元素树。这应该与你的 JSX 源代码非常相似。在这个树的右侧，你有当前选中元素的详细信息，在这种情况下是`App`，它没有定义任何属性。

如果你展开`App`，你会看到它的子 HTML 标记和其他 React 元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/7e88c0de-1ee6-4e1d-8132-7cb0e1b39a06.png)

这是运行`create-react-app`后的默认源代码，因此在`App`元素下没有太多有趣的内容。要进一步探索 React 开发者工具，你需要引入一些更多的组件并在页面上渲染更多的 React 元素。

# 选择 React 元素

实际上有两种方法可以使用 React 开发者工具选择 React 元素。当你打开开发者工具窗格的 React 部分时，React 应用的根元素会自动被选中在元素树中。然而，你可以展开此元素以显示子元素并选择它们。

让我们组合一个简单的应用程序，帮助你使用 React 开发者工具探索页面上渲染的 React 元素。从顶层开始，这是`App`组件：

```jsx
import React from 'react'; 
import MyContainer from './MyContainer'; 
import MyChild from './MyChild'; 

const App = () => ( 
  <MyContainer>
```

```jsx
    <MyChild>child text</MyChild> 
  </MyContainer> 
); 

export default App; 
```

通过查看这个源代码，你可以一览在页面上渲染 React 元素的整体结构。接下来，让我们看看`MyContainer`组件：

```jsx
import React from 'react'; 
import './MyContainer.css'; 

const MyContainer = ({ children }) => ( 
  <section className="MyContainer"> 
    <header> 
      <h1>Container</h1> 
    </header> 
    <article>{children}</article> 
  </section> 
); 

export default MyContainer; 
```

该组件渲染一些标题文本和传递给它的任何子元素。在这个应用程序中，你传递给它一个`MyChild`元素，所以让我们接下来看看这个组件：

```jsx
import React from 'react'; 

const MyChild = ({ children }) => <p>{children}</p>; 

export default MyChild; 
```

现在当你运行`npm start`时，你应该会看到以下内容被渲染出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/36566035-9d1c-41c1-b546-2f4856a88f05.png)

看起来不起眼，但你知道一切都按预期工作。该应用程序足够小，以至于你可以在 React 开发者工具窗格的树视图中看到每个 JSX 元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/65e61109-c368-404f-be29-d81778caa0d1.png)

React 元素和其他元素类型之间有视觉区别，因此它们在树视图中更容易识别。例如，`<MyContainer>`元素是一种颜色，而`<section>`元素是另一种颜色。让我们选择`<MyContainer>`元素，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/7fb9bbf7-602d-41a1-9766-118e5869d1b0.png)

直到这一点，你只选择了`<App>`元素，所以关于这个元素没有什么可显示的——它没有 props 或状态。另一方面，`<MyContainer>`元素确实有要显示的属性。在这种情况下，它有一个`children`属性，因为`<MyChild>`元素被呈现为`<MyContainer>`的子元素。暂时不要担心所选元素右侧显示的具体内容——我们将在下一节详细介绍。

接下来，让我们激活选择工具。它是元素树上方的按钮，上面有一个目标图标。当你点击图标时，它会变成蓝色，让你知道它是激活的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b2795945-0e0b-496f-bd11-8a322ac6cddd.png)

这个工具的想法是允许你点击页面上的元素，并在开发者工具窗格中选择相应的 React 组件。当工具激活时，当你移动到元素上时，元素会被突出显示，让你知道它们是什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/59a7ce26-351f-4e28-b001-3189828643cc.png)

在这里，鼠标指针位于页面上的`<p>`元素上，如小框所示。如果你点击元素，选择工具将在开发者工具窗格中选择适当的元素，然后停用自身。当选择时，`<p>`元素的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/760c5a8d-f00a-4bcf-bc36-dad8b9efc6c0.png)

即使这里选择了`<p>`元素，你看到的是由 React 元素渲染的 props——`<MyChild>`。如果你正在处理页面元素，而不确定哪个 React 元素呈现了它们，使用 React 开发者工具中的选择工具是快速找出的方法。

# 搜索 React 元素

当你的应用程序变得更大时，在 React 开发者工具面板中遍历页面或元素树上的元素效果不佳。你需要一种搜索 React 元素的方法。幸运的是，元素树上方有一个搜索框：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/70d8b0fe-d6ad-433f-a0e8-f0f2b2f869ef.png)

当你在搜索框中输入时，元素在下面的元素树中被过滤。正如你所看到的，匹配的文本也被高亮显示。搜索只匹配元素的名称，这意味着如果你需要从 100 个相同类型的元素中进行过滤，搜索将无法帮助你。然而，即使在这些情况下，搜索也可以删除应用中的其他所有内容，这样你就可以手动浏览一个较小的列表。

如果你选择了高亮搜索复选框，搜索将在主浏览器窗口中高亮显示 React 元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/9b9e7899-1658-4852-a904-d1aa21cb1f28.png)

此页面上的两个 React 元素（`<MyContainer>`和`<MyChild>`）都被高亮显示，因为它们都符合搜索条件`my`。让我们看看当你搜索`child`时会发生什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b4810a54-a129-4f5c-811b-b576283bf1d9.png)

这一次，你可以看到唯一匹配你搜索的 React 元素。它在主浏览器窗口和元素树中都被高亮显示。通过这样搜索，你可以确切地知道在屏幕上选择的元素是什么，当你在元素树中选择它时。

# 检查组件属性和状态

React 遵循声明式范式，因此有助于在浏览器中使用 React 开发者工具等工具，让你看到你的 JSX 标记。这只是你的 React 应用的静态方面——你声明 UI 的元素，让数据控制其余部分。使用相同的工具，你可以观察 props 和 state 在你的应用中流动。为了演示这一点，让我们创建一个简单的列表，一旦挂载就填满自己：

```jsx
import React, { Component } from 'react'; 
import MyItem from './MyItem'; 

class MyList extends Component { 
  timer = null; 
  state = { items: [] };
  componentDidMount() { 
    this.timer = setInterval(() => { 
      if (this.state.items.length === 10) { 
        clearInterval(this.timer); 
        return; 
      } 

      this.setState(state => ({ 
        ...state, 
        items: [ 
          ...state.items, 
          { 
            label: 'Item ${state.items.length + 1}', 
            strikethrough: false 
          } 
        ] 
      })); 
    }, 3000); 
  } 

  componentWillUnmount() { 
    clearInterval(this.timer); 
  } 

  onItemClick = index => () => { 
    this.setState(state => ({ 
      ...state, 
      items: state.items.map( 
        (v, i) => 
          index === i 
            ? { 
                ...v, 
                strikethrough: !v.strikethrough 
              } 
            : v 
      ) 
    })); 
  }; 

  render() { 
    return ( 
      <ul> 
        {this.state.items.map((v, i) => ( 
          <MyItem 
            key={i} 
            label={v.label} 
            strikethrough={v.strikethrough} 
            onClick={this.onItemClick(i)}

          /> 
        ))} 
      </ul> 
    ); 
  } 
} 

export default MyList; 
```

以下是这个组件所做的一切的大致分解：

+   `timer`和`state`: 这些属性被初始化。这个组件的主要状态是一个`items`数组。

+   `componentDidMount()`: 设置一个间隔计时器，每三秒向`items`数组添加一个新值。一旦有十个项目，间隔就会被清除。

+   `componentWillUnmount()`: 确保`timer`属性被强制清除。

+   `onItemClick()`: 接受一个`index`参数，并返回一个索引的事件处理程序。当调用处理程序时，`strikethrough`状态将被切换。

+   `render()`: 渲染一个`<ul>`列表，包含`<MyItem>`元素，传递相关的 props。

这里的想法是慢慢地建立列表，这样你就可以在浏览器工具中观察状态变化发生。然后，通过`MyList`元素，你可以观察传递给它的 props。这个组件看起来是这样的：

```jsx
import React from 'react'; 

const MyItem = ({ label, strikethrough, onClick }) => ( 
  <li 
    style={{ 
      cursor: 'pointer', 
      textDecoration: strikethrough ? 'line-through' : 'none' 
    }} 
    onClick={onClick} 
  > 
    {label} 
  </li> 
); 

export default MyItem; 
```

这是一个简单的列表项。`textDecoration`样式根据`strikethrough` prop 的值而改变。当这个值为 true 时，文本将显示为被划掉的样子。

让我们在浏览器中加载这个应用程序，并观察`MyList`的状态随着间隔处理程序的调用而改变。应用程序加载后，请确保您已经打开并准备好使用 React Developer Tools 窗格。然后，展开`<App>`元素并选择`<MyList>`。您将在右侧看到元素的状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0f159b9e-8a29-4305-8f89-0f2f1fae98b0.png)

左侧呈现的内容与所选`<MyList>`元素的右侧显示的状态相匹配。有一个包含 5 个项目的数组，并且页面上呈现了 5 个项目的列表。这个例子使用间隔计时器随着时间更新状态（直到达到 10 个项目）。如果您仔细观察，您会发现右侧的状态值随着新的列表项的添加而与呈现的内容同步变化。您还可以展开状态中的单个项目以查看它们的值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/795ca4e2-6827-4504-b900-bb0066593c4a.png)

如果您展开`<MyList>`元素，您将看到所有`<MyItem>`元素作为`items`数组状态添加到结果中呈现的结果。从那里，您可以选择`<MyItem>`元素来查看其 props 和状态。在这个例子中，`<MyItem>`元素只有 props，没有状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/09385fb8-63fe-4620-92cb-f6bf5d364426.png)

您可以在左侧的树视图中看到传递给给定元素的 props。与您可以在右侧看到的值相比，这有点难以阅读，右侧显示了所选元素的 prop 值。以下 props 被传递给`<MyItem>`：

+   `label`：要呈现的文本

+   `onClick`：当点击项目时调用的函数

+   `strikethrough`：如果为`true`，则文本将以`strikethrough`样式呈现

您可以观察属性值随着元素重新呈现而改变。在这个应用程序的情况下，当您点击列表项时，处理函数将更改`<MyList>`元素中项目列表的状态。具体来说，被点击的项目的索引将切换其`strikethrough`值。这将导致`<MyItem>`元素重新呈现自身以新的 prop 值。如果您在开发者工具窗格中选择要点击的元素，您可以随时关注 prop 的变化：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/9b6e0451-9f61-4f6d-8d69-9f173c567d36.png)

第一项的文本以`strikethrough`样式呈现。这是因为`strikethrough`属性为`true`。如果你仔细看开发者工具窗格中元素树右侧的属性值，你会看到当它们改变时会闪烁黄色，这是一个方便调试组件的视觉提示。

# 操作元素状态值

React 开发者工具允许你检查所选元素的当前状态。你也可以监视状态的变化，就像前面演示的那样，你可以设置一个间隔定时器来随时间改变元素的状态。元素的状态也可以以有限的方式进行操作。

对于下一个示例，让我们修改`MyList`组件，移除间隔定时器并在构造时简单地填充状态：

```jsx
import React, { Component } from 'react'; 
import MyItem from './MyItem';
class MyList extends Component { 
  timer = null; 
  state = { 
    items: new Array(10).fill(null).map((v, i) => ({ 
      label: 'Item ${i + 1}', 
      strikethrough: false
    })) 
  }; 

  onItemClick = index => () => { 
    this.setState(state => ({ 
      ...state, 
      items: state.items.map( 
        (v, i) => 
          index === i 
            ? { 
                ...v, 
                strikethrough: !v.strikethrough 
              } 
            : v 
      ) 
    })); 
  }; 

  render() { 
    return ( 
      <ul> 
        {this.state.items.map((v, i) => ( 
          <MyItem 
            key={i} 
            label={v.label} 
            strikethrough={v.strikethrough} 
            onClick={this.onItemClick(i)} 
          /> 
        ))} 
      </ul> 
    ); 
  } 
} 

export default MyList; 
```

现在当你运行这个应用时，你会立即看到 10 个项目被渲染出来。除此之外，没有其他改变。你仍然可以点击单个项目来切换它们的`strikethrough`状态。一旦你运行了这个应用，请确保 React 开发者工具浏览器窗格是打开的，这样你就可以选择`<MyList>`元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/5d3028cd-16ff-4ef1-b0e6-7e6605fc6e38.png)

在右侧，你可以看到所选元素的状态。你实际上可以展开`items`数组中的一个对象并改变它的属性值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/2c94a3b4-a5d5-4de6-8050-4e1d551c34fd.png)

`items`数组状态中第一个对象的`label`和`strikethrough`属性被改变。这导致了`<MyList>`和第一个`<MyItem>`元素被重新渲染。如预期的那样，改变的状态在左侧的渲染输出中反映出来。当你需要排除组件没有按照预期更新渲染内容时，这是很方便的。你不需要在组件内部编写测试代码，只需直接进入浏览器中渲染元素的状态并在其中进行操作。

使用 React 开发者工具编辑状态的一个注意事项是，你不能向集合中添加或删除项目。例如，我不能向`items`数组中添加新项目，也不能向数组中的对象添加新属性。对此，你需要在代码中编排你的状态，就像在之前的示例中所做的那样。

# 组件性能分析

通过 React 开发者工具，更容易地对 React 组件的性能进行分析。它更容易发现导致元素重新渲染的更新，当实际上不需要重新渲染时。它还更容易收集给定组件在其生命周期内花费的 CPU 时间以及花费在哪里。

尽管 React 开发者工具不包括任何内存分析工具，但我们将看看如何使用现有的内存开发者工具来专门为 React 元素进行分析。

# 删除协调工作

当渲染 React 元素时，会发生协调。它首先计算将呈现元素的当前状态和 props 的虚拟 DOM 树。然后，将该树与元素的现有树进行比较，假设该树已经至少渲染过一次。React 这样做的原因是因为在与 DOM 交互之前，在 JavaScript 中协调这样的更改更具性能。与简单的 JavaScript 代码相比，DOM 交互相对昂贵。此外，React 协调器还有一些常见情况的启发式方法。

React 为您处理所有这些-您只需要考虑编写声明性的 React 组件。这并不意味着您永远不会遇到性能问题。仅仅因为 JavaScript 中的协调通常比直接操作 DOM 表现更好，并不意味着它是廉价的。因此，让我们组合一个应用程序，突出显示协调的一些潜在问题，然后让我们借助 React 开发者工具来解决这些问题。

我们将创建一个应用程序，用于呈现每个组的组和成员。它将具有更改组数和每个组成员数的控件。最后，每个呈现的组将有一个添加新组的按钮。让我们从`index.js`开始：

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import './index.css'; 
import App from './App'; 
import registerServiceWorker from './registerServiceWorker'; 

const update = () => { 
  ReactDOM.render(<App />, document.getElementById('root')); 
}; 

setInterval(update, 5000); 
update(); 

registerServiceWorker(); 
```

这几乎就像你从`create-react-app`看到的任何`index.js`。不同之处在于有一个使用`setInterval()`调用的`update()`函数。你不会随机地在你的应用程序中抛出一个每五秒重新渲染一次应用程序的间隔计时器。我在这里添加这个只是为了简单地说明重复重新渲染以及这样做的协调后果。在真实的应用程序中，你可能会发现类似的行为，其中你更新组件以保持它们的状态新鲜-这是这种行为的近似。

接下来是主要的`App`组件。这是应用程序状态的所在地，也是大部分功能所在地。让我们先看一下整个文件，然后我会为你解释：

```jsx
import React, { Component } from 'react'; 
import './App.css'; 
import Group from './Group';

class App extends Component { 
  state = { 
    groupCount: 10, 
    memberCount: 20, 
    groups: [] 
  }; 

  refreshGroups = (groups, members) => { 
    this.setState(state => { 
      const groupCount = 
        groups === undefined ? state.groupCount : groups; 
      const memberCount = 
        members === undefined ? state.memberCount : members; 
      return { 
        ...state, 
        groupCount, 
        memberCount, 
        groups: new Array(groupCount).fill(null).map((g, gi) => ({ 
          name: 'Group ${gi + 1}', 
          members: new Array(memberCount) 
            .fill(null) 
            .map((m, mi) => ({ name: 'Member ${mi + 1}' })) 
        })) 
      }; 
    }); 
  }; 

  onGroupCountChange = ({ target: { value } }) => { 
    // The + makes value a number. 
    this.refreshGroups(+value); 
  }; 

  onMemberCountChange = ({ target: { value } }) => { 
    this.refreshGroups(undefined, +value); 
  }; 

  onAddMemberClick = i => () => { 
    this.setState(state => ({ 
      ...state, 
      groups: state.groups.map( 
        (v, gi) => 
          i === gi 
            ? { 
                ...v, 
                members: v.members.concat({ 
                  name: 'Member ${v.members.length + 1}' 
                }) 
              }
            : v 
      ) 
    })); 
  }; 

  componentWillMount() { 
    this.refreshGroups(); 
  } 

  render() { 
    return ( 
      <section className="App"> 
        <div className="Field"> 
          <label htmlFor="groups">Groups</label> 
          <input 
            id="groups" 
            type="range" 
            value={this.state.groupCount} 
            min="1" 
            max="20" 
            onChange={this.onGroupCountChange} 
          /> 
        </div> 
        <div className="Field"> 
          <label htmlFor="members">Members</label> 
          <input 
            id="members" 
            type="range" 
            value={this.state.memberCount} 
            min="1" 
            max="20" 
            onChange={this.onMemberCountChange} 
          /> 
        </div> 
        {this.state.groups.map((g, i) => ( 
          <Group 
            key={i} 
            name={g.name} 
            members={g.members} 
            onAddMemberClick={this.onAddMemberClick(i)} 
          /> 
        ))} 
      </section> 
    ); 
  } 
} 

export default App; 
```

让我们从初始状态开始：

```jsx
state = { 
  groupCount: 10, 
  memberCount: 20, 
  groups: [] 
}; 
```

这个组件管理的状态如下：

+   `groupCount`: 要渲染的组数

+   `memberCount`: 每个组中要渲染的成员数量

+   `groups`: 一个组对象数组

这些值都存储为状态，因为它们可以被改变。接下来，让我们看一下`refreshGroups()`函数：

```jsx
refreshGroups = (groups, members) => { 
  this.setState(state => { 
    const groupCount = 
      groups === undefined ? state.groupCount : groups; 
    const memberCount = 
      members === undefined ? state.memberCount : members; 
    return { 
      ...state, 
      groupCount, 
      memberCount, 
      groups: new Array(groupCount).fill(null).map((g, gi) => ({ 
        name: 'Group ${gi + 1}', 
        members: new Array(memberCount) 
          .fill(null) 
          .map((m, mi) => ({ name: 'Member ${mi + 1}' })) 
      })) 
    }; 
  }); 
}; 
```

在这里不要太担心具体的实现细节。这个函数的目的是在组数和组成员数改变时填充状态。例如，一旦调用，你会有类似以下的状态：

```jsx
{ 
  groupCount: 10, 
  memberCount: 20, 
  groups: [ 
    {
      Name: 'Group 1', 
      Members: [ { name: 'Member 1' }, { name: 'Member 2' } ] 
    }, 
    { 
      Name: 'Group 2', 
      Members: [ { name: 'Member 1' }, { name: 'Member 2' } ] 
    } 
  ] 
} 
```

之所以将这个定义为自己的函数，是因为你将在几个地方调用它。例如，在`componentWillMount()`中调用它，以便组件在首次渲染之前具有初始状态。接下来，让我们看一下事件处理程序函数：

```jsx
onGroupCountChange = ({ target: { value } }) => { 
  this.refreshGroups(+value); 
}; 

onMemberCountChange = ({ target: { value } }) => { 
  this.refreshGroups(undefined, +value); 
}; 

onAddMemberClick = i => () => { 
  this.setState(state => ({ 
    ...state, 
    groups: state.groups.map( 
      (v, gi) => 
        i === gi 
          ? { 
              ...v, 
              members: v.members.concat({ 
                name: 'Member ${v.members.length + 1}' 
              }) 
            } 
          : v 
    ) 
  })); 
}; 
```

这些做以下事情：

+   `onGroupCountChange()`: 通过使用新的组数调用`refreshGroups()`来更新组状态

+   `onMemberCountChange()`: 使用新的成员数量更新组状态中的每个成员对象。

+   `onAddMemberClick()`: 通过在给定索引处添加新成员对象来更新组状态

最后，让我们看一下这个组件渲染的 JSX：

```jsx
render() { 
  return ( 
    <section className="App"> 
      <div className="Field"> 
        <label htmlFor="groups">Groups</label> 
        <input 
          id="groups" 
          type="range" 
          value={this.state.groupCount} 
          min="1" 
          max="20" 
          onChange={this.onGroupCountChange} 
        /> 
      </div> 
      <div className="Field"> 
        <label htmlFor="members">Members</label> 
        <input 
          id="members" 
          type="range" 
          value={this.state.memberCount} 
          min="1" 
          max="20" 
          onChange={this.onMemberCountChange} 
        /> 
      </div> 
      {this.state.groups.map((g, i) => ( 
        <Group 
          key={i} 
          name={g.name} 
          members={g.members} 
          onAddMemberClick={this.onAddMemberClick(i)} 
        /> 
      ))} 
    </section> 
  ); 
} 
```

这个组件渲染两个滑块控件：一个控制组数，一个控制每个组中的成员数。接下来，渲染组列表。为此，有一个`Group`组件，看起来像这样：

```jsx
import React from 'react';
const Group = ({ name, members, onAddMemberClick }) => ( 
  <section> 
    <h4>{name}</h4> 
    <button onClick={onAddMemberClick}>Add Member</button> 
    <ul>{members.map((m, i) => <li key={i}>{m.name}</li>)}</ul> 
  </section> 
); 

export default Group; 
```

这将渲染组的名称，然后是一个添加新成员的按钮，然后是成员列表。当你首次加载页面时，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/1cc3abc1-8e70-4e4e-a114-ff7253f52975.png)

这里只显示了部分输出——在第 1 组中有更多成员，后面还有更多组，使用相同的模式渲染。在使用页面上的任何控件之前，打开 React 开发者工具。然后，查找“高亮更新”复选框：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/69cc8fd5-15bf-4eda-98a2-b083ae7b1cb7.png)

一旦您勾选了这个框，当它们的状态更新时，您渲染的元素将在视觉上得到增强。请记住，您设置了`App`组件每五秒重新渲染一次。每次调用`setState()`时，输出看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a4dfa551-27c4-4e87-88de-f088df5b408d.png)

蓝色边框会在刚刚更新的元素周围闪烁一下。虽然您在这个截图中看不到`<App>`渲染的所有内容，但蓝色边框围绕所有`<Group>`元素，因为它表示`<App>`组件刚刚更新。如果您观察一会儿屏幕，您会注意到蓝色边框每 5 秒出现一次。这表明即使您的元素状态没有改变，它仍在执行协调。它正在遍历可能有数百或数千个树节点，查找任何差异并进行适当的 DOM 更新。

虽然您在这个应用程序中看不到差异，但更复杂的 React 应用程序的累积效果可能会成为问题。在这种特定情况下，由于更新频率，这是一个潜在的问题。

让我们对`App`进行一个补充，看看是否有一种快捷方式可以执行完全的协调：

```jsx
shouldComponentUpdate(props, state) { 
  return ( 
    this.state.groupCount !== state.groupCount || 
    this.state.memberCount !== state.memberCount 
  ); 
} 
```

如果一个 React 组件类有`shouldComponentUpdate()`方法并且返回 false，就会完全避免协调，不会进行重新渲染。通过确保勾选了高亮更新复选框，您可以立即在浏览器中看到变化。如果您坐下来观察一会儿，您会发现没有更多的蓝色边框出现。

更新边框有不同的颜色。您看到的蓝色代表不经常的更新。这取决于更新的频率，可以一直到红色。例如，如果您来回快速滑动组或成员滑块，您应该能够产生红色边框。

然而，请注意，您并不总是能够避免协调。重要的是要对此进行宏观优化。例如，您刚刚添加到`App`组件的解决方案解决了在明显不必要的情况下重新渲染具有大量子元素的巨大组件。与微观优化`Group`组件相比，这是有价值的——它足够小，以至于在这里避免协调并不能节省太多。

你的目标应该是保持高水平，并保持`shouldComponentUpdate()`简单。这是 bug 进入组件的入口点。事实上，您已经引入了一个 bug。尝试点击一个组的“添加成员”按钮，它们不再起作用。这是因为您在`shouldComponentUpdate()`中使用的标准只考虑了`groupCount`和`memberCount`状态。它没有考虑将新成员添加到组中。

要解决这个问题，您必须使用与`shouldComponentUpdate()`中的`groupCount`和`memberState`状态相同的方法。如果所有组的成员总数发生变化，那么您就知道您的应用程序需要重新渲染。让我们在`shouldComponentUpdate()`中进行这个更改：

```jsx
shouldComponentUpdate(props, state) { 
  const totalMembers = ({ groups }) => 
    groups 
      .map(group => group.members.length) 
      .reduce((result, m) => result + m); 

  return ( 
    this.state.groupCount !== state.groupCount || 
    this.state.memberCount !== state.memberCount || 
    totalMembers(this.state) !== totalMembers(state) 
  ); 
} 
```

`totalMembers()`函数以组件状态作为参数，并返回组成员的总数。使用这个函数，你可以添加另一个条件，使用这个函数来比较当前状态中的成员数量和新状态中的成员数量：

```jsx
totalMembers(this.state) !== totalMembers(state) 
```

现在，如果您再次尝试点击“添加成员”按钮，它将如预期般添加成员，因为组件可以检测到状态变化。再次，您需要权衡计算成员数组长度并比较两者的成本，以及在 React DOM 树中执行协调的成本。

# 查找 CPU 密集型组件

`shouldComponentUpdate()`生命周期方法可以实现组件性能的宏观优化。如果明显不需要重新渲染元素，那么让我们完全绕过协调过程。其他时候，协调是无法避免的——元素状态经常发生变化，这些变化需要在 DOM 中反映出来供用户看到。

React 16 的开发版本内置了一些方便的性能工具。它调用相关的浏览器开发工具 API，以记录相关指标，同时记录性能概要。请注意，这与您之前安装的 React 开发者工具浏览器扩展无关；这只是 React 在开发模式下与浏览器交互。

目标是生成 React 特定的时间数据，这样您就不必将其他 20 个浏览器性能指标心算一遍，然后弄清楚它们的含义。一切都为您准备好了。

为了演示这个功能，您可以使用上一节中的相同代码，只需进行一些小的调整。首先，让我们在每个组中提供更多成员：

```jsx
state = { 
  groupCount: 1, 
  memberCount: 200, 
  groups: [] 
}; 
```

我们增加这个数字的原因是，当您操作控件时，应用的性能会下降——您希望使用性能开发工具来捕获这种性能下降。接下来，让我们增加成员字段的最大滑块值：

```jsx
<div className="Field"> 
  <label htmlFor="members">Members</label> 
  <input 
    id="members" 
    type="range" 
    value={this.state.memberCount}
    min="1" 
    max="200" 
    onChange={this.onMemberCountChange} 
  /> 
</div> 
```

就是这样。现在当您在浏览器中查看此应用时，它应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d94284d1-cb45-41aa-9581-48035d414df0.png)

在更改任何这些滑块数值之前，请确保您的开发者工具窗格已打开，并且已选择“性能”选项卡：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/6c402524-13d2-4263-b2f4-207eb195edd9.png)

接下来，点击左侧的圆圈图标开始记录性能概要。按钮将变为红色，您会看到一个状态对话框出现，表示已开始分析：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/1deafabf-f16c-473c-912a-a928c7235061.png)

现在您正在记录，将“组”滑块滑动到最右边。当您接近右边时，您可能会注意到 UI 有些延迟，这是件好事，因为这正是您想要设计的。一旦滑块滑到最右边，点击开始录制时点击的红色圆圈来停止录制。您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/8a141de3-4c30-4c9a-94e2-2be50a38a43f.png)

我扩大了左侧的用户定时标签，因为这里显示了所有 React 特定的时间。在这个图表中，时间从左到右流动。某件事情越宽，它花费的时间就越长。您可能会注意到，当您接近滑块的右侧时，性能会变差（这也可能与您在滑块控制中注意到的延迟相吻合）。

因此，让我们探索一下这些数据的含义。我们将查看最右边的数据，因为这里性能真的下降了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/1d20af25-e877-45b5-bebb-b1a522feceb2.png)

这个标签告诉您，React 树协调需要 78 毫秒来执行。并不是非常慢，但足够慢以至于对用户体验产生了实质性影响。当您逐个查看这些标签时，您应该能更好地了解为什么协调过程需要这么长时间。让我们看下一个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/fb5e831e-1891-4aac-8cad-7ecfac962b94.png)

这很有趣：`App [update]` 标签告诉你，在 `App` 组件中的状态更新花费了 78 毫秒。在这一点上，你知道 `App` 中的状态更新导致了 React 协调过程花费了 78 毫秒。让我们跳到下一个级别。在这个级别，有两种颜色。让我们看看黄色代表什么：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0ee7953c-f898-4e19-b24c-1cc5e0c397dc.png)

通过悬停在黄色的片段上，你可以看到 `Group [update]` 花费了 7.7 毫秒来更新一个 `Group` 组件。这可能是一个微不足道的时间，可能无法以任何有意义的方式改进。然而，看一下代表 `Group` 更新的黄色片段的数量。所有这些单位数时间片段加起来占据了整体协调时间的相当大一部分。最后，让我们看看棕色：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/942e8e87-2081-4841-8f72-8360e6901a41.png)

这个标签，`Group [mount]`，表示安装一个新的 `Group` 组件花费了 6.5 毫秒。再一次，这是一个小数字，但有几个片段。

在这一点上，你已经一直深入到组件层次结构的底部，以检查是什么导致了你的性能问题。这里的要点是什么？你确定了 React 执行协调所花费的大部分时间发生在 `Group` 组件中。每次渲染 `Group` 组件时，只需要几毫秒的时间来完成，但有很多组。

感谢浏览器开发者工具中的性能图表，现在你知道改变你的代码并不会有所收获——你不会以任何有意义的方式改善单位数毫秒的时间。在这个应用程序中，解决你在将滑块向右移动时感到的延迟的唯一方法是以某种方式减少在页面上呈现的元素数量。另一方面，你可能会注意到一些 React 性能指标有 50 毫秒，或在某些情况下有数百毫秒。你可以轻松修复你的代码以提供更好的用户体验。关键是，如果没有像你在本节中使用过的性能开发工具，你将永远不知道实际上有什么会产生差异。

当您作为用户与应用程序交互时，通常会感觉到性能问题。但验证组件是否存在性能问题的另一种方法是查看显示在 React 指标上方的帧速率，呈绿色。它显示了在相应的 React 代码下渲染帧所花费的时间。您刚刚构建的示例在滑块位于左侧时以每秒 40 帧开始，但当滑块移至最右侧时以每秒 10 帧结束。

# 摘要

在本章中，您了解了可以直接通过 Web 浏览器使用的 React 工具。这里的首选工具是一个名为 React Developer Tools 的 Chrome/Firefox 扩展程序。该扩展程序为浏览器的原生开发者工具添加了特定于 React 的功能。安装了该扩展程序后，您学会了如何选择 React 元素以及如何按标签名称搜索 React 元素。

接下来，您查看了 React Developer Tools 中所选 React 组件的属性和状态值。这些值会自动更新，因为它们被应用程序更改。然后，您学会了如何在浏览器中直接操作元素状态。这里的限制是您无法向集合中添加或删除值。

最后，您学会了如何在浏览器中对 React 组件的性能进行分析。这不是 React Developer Tools 的功能，而是 React 16 的开发版本自动执行的。使用这样的分析可以确保在遇到性能问题时您正在解决正确的问题。本章中您查看的示例表明，代码实际上并没有问题，问题在于一次在屏幕上渲染了太多的元素。

在下一章中，您将构建一个基于 Redux 的 React 应用程序，并使用 Redux DevTools 来监视应用程序的状态。
