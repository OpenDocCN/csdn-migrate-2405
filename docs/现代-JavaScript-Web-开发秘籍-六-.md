# 现代 JavaScript Web 开发秘籍（六）

> 原文：[`zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6`](https://zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：测试和调试您的移动应用程序

在本章中，我们将研究以下配方：

+   使用 Jest 编写单元测试

+   添加快照测试

+   测量测试覆盖率

+   使用 Storybook 预览组件

+   使用 react-native-debugger 调试您的应用程序

+   使用 Reactotron 进行替代方式的调试

# 介绍

在上一章中，我们看到了如何开发`React Native`（RN）移动应用程序，以及我们如何与`Node`和`React`一样，让我们通过查看测试和调试我们的应用程序来完成移动应用程序的开发过程。

# 使用 Jest 编写单元测试

进行 RN 的单元测试不会太让人惊讶，因为我们将能够重用之前学到的大部分知识（例如，使用`Jest`也与快照一起使用，或者如何测试`Redux`），除了一些必须注意的小细节，我们将会看到。

在这个配方中，我们将看看如何为 RN 设置单元测试，沿用我们已经为`Node`和`React`做的工作。

# 准备工作

无论您是使用 CRAN（就像我们一样）还是使用`react-native init`创建移动应用程序，对`Jest`的支持都是内置的；否则，您将不得不自己安装它，就像我们在第五章的*单元测试您的代码*部分中看到的那样，*测试和调试您的服务器*。根据您创建项目的方式，在`package.json`中的`Jest`配置会有所不同；我们不必做任何事情，但是请参阅[`jestjs.io/docs/en/tutorial-react-native.html#setup`](https://jestjs.io/docs/en/tutorial-react-native.html#setup)以获取替代方案。我们将不得不添加一些我们之前使用过的包，但仅此而已：

```js
npm install enzyme enzyme-adapter-react-16 react-test-renderer redux-mock-store --save
```

完成后，我们可以像以前一样编写测试。让我们看一个例子。

# 如何做...

在本书的早些时候，我们为国家和地区应用程序编写了一些测试，因为我们已经在 RN 中重写了它，为什么不也重写测试呢？这将使我们能够验证为 RN 编写单元测试与为普通的`React`编写单元测试并没有太大的不同。我们已经为`<RegionsTable>`组件编写了测试；让我们在这里检查一下：

```js
// Source file: src/regionsStyledApp/regionsTable.test.js

/* @flow */

import React from "react";
import Enzyme from "enzyme";
import Adapter from "enzyme-adapter-react-16";

import { RegionsTable } from "./regionsTable.component";

Enzyme.configure({ adapter: new Adapter() });

const fakeDeviceData = {
 isTablet: false,
 isPortrait: true,
 height: 1000,
 width: 720,
 scale: 1,
 fontScale: 1
};

describe("RegionsTable", () => {
    it("renders correctly an empty list", () => {
 const wrapper = Enzyme.shallow(
 <RegionsTable deviceData={fakeDeviceData} list={[]} />
 );
 expect(wrapper.contains("No regions."));
    });

    it("renders correctly a list", () => {
 const wrapper = Enzyme.shallow(
            <RegionsTable
 deviceData={fakeDeviceData}
                list={[
                    {
                        countryCode: "UY",
                        regionCode: "10",
                        regionName: "Montevideo"
                    },
                    {
                        countryCode: "UY",
                        regionCode: "9",
                        regionName: "Maldonado"
                    },
                    {
                        countryCode: "UY",
                        regionCode: "5",
                        regionName: "Cerro Largo"
                    }
                ]}
            />
        );

 expect(wrapper.contains("Montevideo"));
 expect(wrapper.contains("Maldonado"));
 expect(wrapper.contains("Cerro Largo"));
    });
});
```

差异真的很小，大部分都是相同的代码：

+   我们不得不添加`fakeDeviceData`，但那只是因为我们的 RN 组件需要它

+   我们将`Enzyme.render()`更改为`Enzyme.shallow()`

+   我们改变了使用`wrapper`对象来直接检查包含的文本的方式，使用``wrapper.contains()``

有关所有可用包装器方法的完整（而且很长！）列表，请查看[`github.com/airbnb/enzyme/blob/master/docs/api/shallow.md`](https://github.com/airbnb/enzyme/blob/master/docs/api/shallow.md)。

我们还可以看一下`<CountrySelect>`的测试，其中涉及模拟事件。我们可以跳过与`React`版本几乎相同的测试；让我们专注于我们原始测试中的最后一个：

```js
// Source file: src/regionsStyledApp/countrySelect.test.js

/* @flow */
import React from "react";
import Enzyme from "enzyme";
import Adapter from "enzyme-adapter-react-16";

import { CountrySelect } from "./countrySelect.component";

Enzyme.configure({ adapter: new Adapter() });

const threeCountries = [
    {
        countryCode: "UY",
        countryName: "Uruguay"
    },
    {
        countryCode: "AR",
        countryName: "Argentina"
    },
    {
        countryCode: "BR",
        countryName: "Brazil"
    }
];

const fakeDeviceData = {
    isTablet: false,
    isPortrait: true,
    height: 1000,
    width: 720,
    scale: 1,
    fontScale: 1
}

describe("CountrySelect", () => {
    // 
    // *some tests omitted*
    //

    it("correctly calls onSelect", () => {
        const mockGetCountries = jest.fn();
        const mockOnSelect = jest.fn();

        const wrapper = Enzyme.shallow(
            <CountrySelect
                deviceData={fakeDeviceData}
                loading={false}
                currentCountry={""}
                onSelect={mockOnSelect}
                getCountries={mockGetCountries}
                list={threeCountries}
            />
        );

 wrapper.find("Picker").simulate("ValueChange", "UY");

 expect(mockGetCountries).not.toHaveBeenCalled();
 expect(mockOnSelect).toHaveBeenCalledTimes(1);
 expect(mockOnSelect).toHaveBeenCalledWith("UY");
    });
});
```

我们为`React`和 RN 编写测试的关键区别在于我们`.find()`要点击的元素的方式（RN 使用`Picker`组件，而不是一组`option`元素），以及我们模拟的事件（`"ValueChange"`而不是`"change"`）。除此之外，代码与之前的代码相同。

对于原生模块，您可能需要使用模拟来模拟预期的行为。我们的代码中没有使用这样的模块，但是如果您需要其中任何一个，可以使用我们在第五章的*测试和调试您的服务器*中看到的相同的模拟样式，以及对`React`本身的模拟样式在第十章的*测试您的应用程序*中。

在 RN 组件测试中已经讨论了一些差异，因为在测试操作或减速器时代码没有差异。这些使用相同的功能单元测试风格，不涉及任何特定的 RN 功能，所以我们没有更多可说的了。在下一节中，我们将查看我们的测试运行。

# 它是如何工作的...

运行测试与以前一样，只需一个命令：

```js
npm test
```

输出如下截图所示——请注意，我们还运行了一些从`React`章节复制过来的测试，没有任何更改，它们也表现得很完美：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/f2bb19d5-78b8-4f57-944f-2b23fc48df1c.png)

我们所有组件的测试都通过了

因此，除了需要使用浅渲染，并可能需要以不同的方式访问元素或模拟事件，为 RN 编写单元测试基本上与为`React`编写单元测试相同，这是个好消息。然而，我们忘了一件事——快照测试怎么样？让我们继续。

# 添加快照测试

使用 RN 进行快照测试是一个惊喜，因为你不需要改变之前的工作方式。让我们看几个例子，你就会相信。

# 如何做...

我们已经在第十章的*使用快照测试更改*部分中看到了快照测试。恰好，相同的代码在 RN 应用中也能完美运行，而不需要任何特定的更改，除了那些取决于代码变化的部分。让我们考虑以下示例。我们之前开发的`<RegionsTable>`组件在 RN 中有一个额外的 prop：`deviceData`。因此，我们可以复制原始快照测试代码，然后只需添加新的 prop，如下所示：

```js
// Source file: src/regionsStyledApp/regionsTable.snapshot.test.js

/* @flow */

import React from "react";
import TestRenderer from "react-test-renderer";

import { RegionsTable } from "./regionsTable.component";

const fakeDeviceData = {
 isTablet: false,
 isPortrait: true,
 height: 1000,
 width: 720,
 scale: 1,
 fontScale: 1
};

describe("RegionsTable", () => {
    it("renders correctly an empty list", () => {
        const tree = TestRenderer.create(
            <RegionsTable deviceData={fakeDeviceData} list={[]} />
        ).toJSON();
        expect(tree).toMatchSnapshot();
    });

    it("renders correctly a list", () => {
        const tree = TestRenderer.create(
            <RegionsTable
                deviceData={fakeDeviceData}
                list={[
                    {
                        countryCode: "UY",
                        regionCode: "10",
                        regionName: "Montevideo"
                    },
                    {
                        countryCode: "UY",
                        regionCode: "9",
                        regionName: "Maldonado"
                    },
                    {
                        countryCode: "UY",
                        regionCode: "5",
                        regionName: "Cerro Largo"
                    }
                ]}
            />
        ).toJSON();
        expect(tree).toMatchSnapshot();
    });
});
```

如果你愿意比较版本，你会发现唯一改变的部分是我用粗体标出的部分，它们与不同的组件有关，而不是与任何 RN 特定的东西有关。如果你为`<CountrySelect>`组件编写快照测试，你会发现完全相同的结果：唯一必要的更改与其新的 props（`deviceData`，`currentCountry`）有关，但没有其他困难。

为了多样化，让我们为我们的`<Main>`组件添加快照测试。这里有两个有趣的细节：

+   由于我们的组件在纵向或横向模式下呈现不同，我们应该有两个测试；和

+   由于该组件包含连接的组件，我们不要忘记添加`<Provider>`组件，否则连接将无法建立。

代码如下；特别要注意不同的设备数据和`<Provider>`的包含：

```js
// Source file: src/regionsStyledApp/main.snapshot.test.js

/* @flow */

import React from "react";
import { Provider } from "react-redux";
import TestRenderer from "react-test-renderer";

import { Main } from "./main.component";
import { store } from "./store";

const fakeDeviceData = {
    isTablet: false,
    isPortrait: true,
    height: 1000,
    width: 720,
    scale: 1,
    fontScale: 1
};

describe("Main component", () => {
    it("renders in portrait mode", () => {
        const tree = TestRenderer.create(
 <Provider store={store}>
                <Main
                    deviceData={{ ...fakeDeviceData, isPortrait: true }}
                />
 </Provider>
        ).toJSON();
        expect(tree).toMatchSnapshot();
    });

    it("renders in landscape mode", () => {
        const tree = TestRenderer.create(
 <Provider store={store}>
                <Main
                    deviceData={{ ...fakeDeviceData, isPortrait: false }}
                />
 </Provider>
        ).toJSON();
        expect(tree).toMatchSnapshot();
    });
});
```

# 它是如何工作的...

由于我们所有快照测试的文件名都以`.snapshot.js`结尾，我们可以用一个命令运行所有快照测试：

```js
npm test snapshot
```

第一次运行测试时，与以前一样，将创建快照：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/38d8d4ed-7f20-4ddc-b976-e694a40b4e88.png)

与 React 一样，第一次运行将为组件创建快照

如果我们检查`__snapshots__`目录，我们会发现其中有三个生成的`.snap`文件。它们的格式与我们之前开发的`React`示例相同。让我们看一下之前展示的`<RegionsTable>`的一个：

```js
// Jest Snapshot v1, https://goo.gl/fbAQLP

exports[`RegionsTable renders correctly a list 1`] = `
<RCTScrollView
  style={
    Array [
      undefined,
      Object {
        "backgroundColor": "lightgray",
      },
    ]
  }
>
  <View>
    <View>
      <Text
        accessible={true}
        allowFontScaling={true}
        ellipsizeMode="tail"
      >
        Cerro Largo
      </Text>
    </View>
    <View>
      <Text
        accessible={true}
        allowFontScaling={true}
        ellipsizeMode="tail"
      >
        Maldonado
      </Text>
    </View>
    <View>
      <Text
        accessible={true}
        allowFontScaling={true}
        ellipsizeMode="tail"
      >
        Montevideo
      </Text>
    </View>
  </View>
</RCTScrollView>
`;

exports[`RegionsTable renders correctly an empty list 1`] = `
<View
  style={undefined}
>
  <Text
    accessible={true}
    allowFontScaling={true}
    ellipsizeMode="tail"
  >
    No regions.
  </Text>
</View>
`;
```

如果将来再次运行测试，而且没有任何更改，那么结果将是三个 PASS 绿色消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/9bde6097-450b-47fa-87d8-8c1824c948cc.png)

我们的快照测试都成功了

一切都很顺利，所以我们可以断言编写快照测试不会给 RN 测试增加任何复杂性，并且可以毫无困难地进行。

# 测量测试覆盖率

就像我们在第五章的*测试和调试您的服务器*和第十章的*测试您的应用程序*中为`Node`和`React`做的那样，我们希望对我们的测试覆盖率进行测量，以了解我们的工作有多彻底，并能够检测到需要更多工作的代码片段。幸运的是，我们将能够使用之前使用的相同工具来管理，因此这个步骤将很容易实现。

# 如何做...

CRAN 提供的应用程序设置包括我们之前看到的`Jest`，而`Jest`为我们提供了所需的覆盖选项。首先，我们需要添加一个简单的脚本，以便用一些额外的参数运行我们的测试套件：

```js
"scripts": {
    .
    .
    .
    "test": "jest",
 "coverage": "jest --coverage --no-cache",
},
```

就这些了，我们没有其他事情要做；让我们看看它是如何工作的！

# 它是如何工作的...

运行测试很简单；我们只需要使用新的脚本：

```js
npm run coverage
```

整个套件将以与本章前几节相同的方式运行，但最后将生成一个文本摘要。与之前一样，颜色将被使用：绿色表示覆盖良好（在测试方面），黄色表示中等覆盖率，红色表示覆盖率低或没有覆盖：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/c128c727-66e1-4504-8ad8-0ca091acd55f.png)

使用启用覆盖选项的 Jest 生成了与我们在 Node 和 React 中看到的相同类型的结果

我们还可以检查生成的 HTML 文件，这些文件可以在`/coverage/lcov-report`中找到。在那里打开`index.html`文件，你将得到一个交互式版本的报告，就像下面的截图一样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/6786267b-dbbf-4c1d-9778-641d5de3e382.png)

生成的 HTML 报告是交互式的，可以让你看到你在测试中错过了什么

例如，如果你想知道为什么`deviceHandler.component.js`文件得分如此之低（不要紧，你没有为它编写测试；所有的代码都应该被覆盖，如果可能的话），你可以点击它并查看原因。在我们的情况下，`onLayoutHandler`代码（逻辑上）从未被调用，因此降低了该文件的覆盖率：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/0523cce4-3e14-46ad-a739-3307671a681b.png)

点击文件将显示哪些行被执行，哪些行（红色背景）被忽略

要查看如何禁用未覆盖的报告行，或者对于你不想考虑的情况，可以查看[`github.com/gotwarlost/istanbul/blob/master/ignoring-code-for-coverage.md`](https://github.com/gotwarlost/istanbul/blob/master/ignoring-code-for-coverage.md)。

# 使用 Storybook 预览组件

`Storybook`，我们在第六章的*Simplifying component development with Storybook*部分中介绍的`React`工具，也可以用来帮助开发组件，因此在这个教程中，让我们看看如何使用它来简化我们的工作。

# 准备工作

安装`Storybook`很简单，与之前的操作类似；`react-native-storybook-loader`包将允许我们将`*.story.js`文件放在任何我们想要的地方，并且无论如何都能找到它们。第二个命令将需要一些时间，安装许多包；请注意！此外，将在你的目录根目录下创建一个`storybook`目录。使用以下命令安装`Storybook`：

```js
npm install @storybook/cli react-native-storybook-loader --save-dev
npx storybook init
```

`storybook/Stories`目录可以安全地删除，因为我们将把我们的故事和被演示的组件放在其他地方，就像我们在本书的前面部分所做的那样。

在使用 CRNA 创建的 RN 应用程序中运行`Storybook`需要额外的步骤：提供一个适当的`App.js`文件。实现这一点的最简单方法是使用一行文件：

```js
export default from './storybook';
```

然而，这是一个问题——你将如何运行你的应用程序？当然，你可以有两个不同的`App.storybook.js`和`App.standard.js`文件，并将其中一个复制到`App.js`，但如果手动完成，这很快就会变得无聊。当然，你可以使用一些`npm`脚本。以下命令适用于 Linux 或 macOS 设备，使用`cp`命令来复制文件，但对于 Windows 设备需要进行小的更改：

```js
"scripts": {
 "start": "cp App.standard.js App.js && react-native-scripts start",
    .
    .
    .
 "storybook": "cp App.storybook.js App.js && rnstl && storybook start -p 7007"
},
```

我们还需要在`package.json`中添加一些加载器的配置。以下内容使加载器在`./src`目录中查找`*.story.js`文件，并生成一个带有找到的故事的`storyLoader.js`文件：

```js
"config": {
    "react-native-storybook-loader": {
        "searchDir": [
            "./src"
        ],
        "pattern": "**/*.story.js",
        "outputFile": "./storybook/storyLoader.js"
    }
},
```

最后，我们将不得不修改`storybook/index.js`，如下所示：

```js
import { getStorybookUI, configure } from "@storybook/react-native";

import { loadStories } from "./storyLoader";

configure(loadStories, module);
const StorybookUI = getStorybookUI({ port: 7007, onDeviceUI: true });

export default StorybookUI;
```

我们现在已经设置好了，让我们写一些故事！

查看[`github.com/storybooks/storybook/tree/master/app/react-native`](https://github.com/storybooks/storybook/tree/master/app/react-native)了解 RN 的`Storybook`的更多文档，以及[`github.com/elderfo/react-native-storybook-loader`](https://github.com/elderfo/react-native-storybook-loader)了解我们正在使用的加载程序的详细信息。

# 如何做...

让我们写一些故事。我们可以从`<RegionsTable>`组件开始，这很简单：它不包括任何操作，只显示数据。我们可以写两种情况：当提供空的地区列表时，以及当提供非空列表时。我们不必过多考虑所需的假数据，因为我们可以重用我们为单元测试编写的内容！考虑以下代码：

```js
// Source file: src/regionsStyledApp/regionsTable.story.js

/* @flow */

import React from "react";
import { storiesOf } from "@storybook/react-native";

import { Centered } from "../../storybook/centered";
import { RegionsTable } from "./regionsTable.component";

const fakeDeviceData = {
    isTablet: false,
    isPortrait: true,
    height: 1000,
    width: 720,
    scale: 1,
    fontScale: 1
};

storiesOf("RegionsTable", module)
    .addDecorator(getStory => <Centered>{getStory()}</Centered>)
    .add("with no regions", () => (
        <RegionsTable deviceData={fakeDeviceData} list={[]} />
    ))
    .add("with some regions", () => (
        <RegionsTable
            deviceData={fakeDeviceData}
            list={[
                {
                    countryCode: "UY",
                    regionCode: "10",
                    regionName: "Montevideo"
                },
                {
                    countryCode: "UY",
                    regionCode: "9",
                    regionName: "Maldonado"
                },
                {
                    countryCode: "UY",
                    regionCode: "5",
                    regionName: "Cerro Largo"
                }
            ]}
        />
    ));
```

添加一个修饰器来使显示的组件居中只是为了清晰起见：必要的`<Centered>`代码很简单，并且需要一点我们在上一章中看到的样式：

```js
// Source file: storybook/centered.js

/* @flow */

import React from "react";
import { View, StyleSheet } from "react-native";
import PropTypes from "prop-types";

const centerColor = "white";
const styles = StyleSheet.create({
 centered: {
 flex: 1,
 backgroundColor: centerColor,
 alignItems: "center",
 justifyContent: "center"
 }
});

export class Centered extends React.Component<{ children: node }> {
    static propTypes = {
        children: PropTypes.node.isRequired
    };

    render() {
        return <View style={styles.centered}>{this.props.children}</View>;
    }
}
```

现在，为`<CountrySelect>`设置故事更有趣，因为我们有操作。我们将为组件提供两个操作：当用户点击它以选择一个国家时，以及用于获取国家列表的`getCountries()`回调的另一个操作：

```js
// Source file: src/regionsStyledApp/countrySelect.story.js

/* @flow */

import React from "react";
import { storiesOf } from "@storybook/react-native";
import { action } from "@storybook/addon-actions";

import { Centered } from "../../storybook/centered";
import { CountrySelect } from "./countrySelect.component";

const fakeDeviceData = {
    isTablet: false,
    isPortrait: true,
    height: 1000,
    width: 720,
    scale: 1,
    fontScale: 1
};

storiesOf("CountrySelect", module)
    .addDecorator(getStory => <Centered>{getStory()}</Centered>)
    .add("with no countries yet", () => (
        <CountrySelect
            deviceData={fakeDeviceData}
            loading={true}
            currentCountry={""}
            onSelect={action("click:country")}
            getCountries={action("call:getCountries")}
            list={[]}
        />
    ))
    .add("with three countries", () => (
        <CountrySelect
            deviceData={fakeDeviceData}
            currentCountry={""}
            loading={false}
            onSelect={action("click:country")}
            getCountries={action("call:getCountries")}
            list={[
                {
                    countryCode: "UY",
                    countryName: "Uruguay"
                },
                {
                    countryCode: "AR",
                    countryName: "Argentina"
                },
                {
                    countryCode: "BR",
                    countryName: "Brazil"
                }
            ]}
        />
    ));
```

我们现在已经准备好了；让我们看看这是如何工作的。

# 它是如何工作的...

要查看`Storybook`应用程序，我们需要使用我们在前一节中编辑的脚本。首先运行`storybook`脚本（最好在单独的控制台中执行此操作），然后运行应用程序本身，如下所示：

```js
// *at one terminal*
npm run storybook

// *and at another terminal*
npm start
```

第一个命令产生了一些输出，让我们确认我们的脚本是否有效，并且找到了所有的故事。以下代码略作编辑以便更清晰：

```js
> npm run storybook

> chapter12b@0.1.0 storybook /home/fkereki/JS_BOOK/modernjs/chapter12
> cp App.storybook.js App.js && rnstl && storybook start -p 7007

Generating Dynamic Storybook File List

Output file: /home/fkereki/JS_BOOK/modernjs/chapter12/storybook/storyLoader.js
Patterns: ["/home/fkereki/JS_BOOK/modernjs/chapter12/src/**/*.story.js"]
Located 2 files matching pattern '/home/fkereki/JS_BOOK/modernjs/chapter12/src/**/*.story.js' 
Compiled story loader for 2 files:
 /home/fkereki/JS_BOOK/modernjs/chapter12/src/regionsStyledApp/countrySelect.story.js
 /home/fkereki/JS_BOOK/modernjs/chapter12/src/regionsStyledApp/regionsTable.story.js
=> Loading custom .babelrc from project directory.
=> Loading custom addons config.
=> Using default webpack setup based on "Create React App".
Scanning 1424 folders for symlinks in /home/fkereki/JS_BOOK/modernjs/chapter12/node_modules (18ms)

RN Storybook started on => http://localhost:7007/

Scanning folders for symlinks in /home/fkereki/JS_BOOK/modernjs/chapter12/node_modules (27ms)

+----------------------------------------------------------------------+
|                                                                      |
| Running Metro Bundler on port 8081\.                                  |
|                                                                      |
| Keep Metro running while developing on any JS projects. Feel free to |
| close this tab and run your own Metro instance if you prefer.        |
|                                                                      |
| https://github.com/facebook/react-native                             |
|                                                                      |
+----------------------------------------------------------------------+

Looking for JS files in
 /home/fkereki/JS_BOOK/modernjs/chapter12/storybook
 /home/fkereki/JS_BOOK/modernjs/chapter12
 /home/fkereki/JS_BOOK/modernjs/chapter12 

Metro Bundler ready.

webpack built bab22529b80fbd1ce576 in 2918ms
Loading dependency graph, done.
```

我们可以打开浏览器，得到一个与我们为 Web 应用程序和`React`获得的视图非常相似的视图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/cd5e5f68-4756-403d-b280-a662dd677a7a.png)

您可以在侧边栏中选择故事，应用程序将显示它们

如果您在菜单中选择一个故事，应用程序将显示它，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/bdad9c0b-3193-40df-bf36-ff2cd0983ab6.png)

应用程序会在浏览器中显示您选择的故事

您还可以通过按压前面截图左上角的汉堡菜单来选择在应用程序本身中显示哪个故事。结果选择菜单显示如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/ca2bb2b9-4837-43d3-b0ee-28281efa21d9.png)

该应用程序还允许您选择要显示的故事

最后，您可以在浏览器中看到操作。让我们想象一下，您打开了包含三个国家的国家列表的故事：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/fdcfc50d-9a8a-4ae5-a6da-dd6cd39b0352.png)

国家选择器让您与操作进行交互

如果您点击巴西，浏览器将显示已触发的操作。首先，我们可以看到当`getCountries()`回调被调用时，会出现 call:getCountries，然后当您点击一个选项时会出现 click:country。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/db13f2c1-3c0b-438d-8046-6b6ffd1625ef.png)

与 Web 应用程序一样，您可以与故事互动，并查看调用了哪些操作以及使用了哪些参数

因此，我们已经看到，添加故事实际上与 Web 应用程序相同，并且您还可以获得额外的工具来帮助开发-您应该考虑这一点。

# 使用 react-native-debugger 调试您的应用程序

调试 RN 应用程序比处理 Web 应用程序更难，因为您想要做的一切都是远程完成的；您不能在移动设备上运行功能齐全的调试器。有几种工具可以帮助您解决这个问题，在本节中，我们将考虑一个“万能”工具`react-native-debugger`，它包括一个强大的三合一实用程序，其中大多数（如果不是全部）您的需求应该得到满足。

您需要进行彻底调试的基本工具（我们之前已经遇到过）如下：

+   Chrome 开发者工具，网址为[`developers.google.com/web/tools/chrome-devtools/`](https://developers.google.com/web/tools/chrome-devtools/)，用于访问控制台等

+   `React devtools`（独立版本）网址为[`github.com/facebook/react-devtools`](https://github.com/facebook/react-devtools)，用于处理组件

+   `Redux DevTools`扩展，网址为[`github.com/zalmoxisus/redux-devtools-extension`](https://github.com/zalmoxisus/redux-devtools-extension)，用于检查操作和状态

当然，您可以单独安装它们，并与三者一起使用，但将它们全部放在一起无疑更简单，因此我们将遵循这个方法。所以，让我们开始调试我们的代码吧！

您可以在[`facebook.github.io/react-native/docs/debugging`](http://facebook.github.io/react-native/docs/debugging)了解 RN 调试的基础知识，并在[`github.com/jhen0409/react-native-debugger`](https://github.com/jhen0409/react-native-debugger)学习`react-native-debugger`。

# 入门

我们需要安装几个软件包才能让一切正常工作。首先，只需从[`github.com/jhen0409/react-native-debugger/releases`](https://github.com/jhen0409/react-native-debugger/releases)的发布页面获取`react-native-debugger`可执行文件。安装只需解压下载的文件；执行只需在解压后的目录中运行可执行文件。

我们需要安装一些软件包，以便将我们的应用程序连接到`react-native-debugger`，可以通过模拟器或实际设备上运行以下命令来获取这些软件包。让我们使用以下命令安装这些软件包：

```js
npm install react-devtools remote-redux-devtools --save-dev
```

我们现在已经准备好了一切。让我们看一下如何将工具（主要是 Redux 调试器）集成到我们的应用程序中的一些细节，然后我们就可以开始调试了。

# 如何做...

让我们看看如何设置我们的应用程序，以便我们可以使用我们的调试工具。首先，我们需要在存储创建代码中进行简单更改，添加几行，如下所示：

```js
// Source file: src/regionsStyledApp/store.js

/* @flow */

import { createStore, applyMiddleware } from "redux";
import thunk from "redux-thunk";
import { composeWithDevTools } from "redux-devtools-extension";

import { reducer } from "./world.reducer";

export const store = createStore(
    reducer,
 composeWithDevTools(applyMiddleware(thunk))
);
```

仅仅是为了让我们能够实际获得一些调试消息，我在整个代码中添加了各种`console.log()`和`console.error()`调用。为了保持一致，我想使用`debug`（来自[`www.npmjs.com/package/debug`](https://www.npmjs.com/package/debug)），就像我们在本书中之前所做的那样，但它不起作用，因为它需要`LocalStorage`，而在 RN 中，您将使用不同的 API`AsyncStorage`。只是举个例子，我们将查看`world.actions.js`的一些日志输出。我没有打扰记录成功的 API 调用的输出，因为我们将通过`react-native-debugger`获得，我们将看到：

```js
// Source file: src/regionsStyledApp/world.actions.js

.
.
.

export const getCountries = () => async dispatch => {
 console.log("getCountries: called");
    try {
        dispatch(countriesRequest());
        const result = await getCountriesAPI();
        dispatch(countriesSuccess(result.data));
    } catch (e) {
 console.error("getCountries: failure!");
        dispatch(countriesFailure());
    }
};

export const getRegions = (country: string) => async dispatch => {
 console.log("getRegions: called with ", country);
    if (country) {
        try {
            dispatch(regionsRequest(country));
            const result = await getRegionsAPI(country);
            dispatch(regionsSuccess(result.data));
        } catch (e) {
 console.error("getRegions: failure with API!");
            dispatch(regionsFailure());
        }
    } else {
 console.error("getRegions: failure, no country!");
        dispatch(regionsFailure());
    }
};
```

我们已经准备就绪，让我们试一试。

# 它是如何工作的...

首先，使用以下命令运行您的应用程序：

```js
npm start
```

在您的设备上（无论是真实设备还是模拟设备），通过摇动（在实际设备上）或在 macOS 上使用 command + m 或在 Windows 或 Linux 上使用 Ctrl + M 来访问开发者菜单。至少，您希望启用远程 JS 调试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/3b4d9410-50e0-43b2-aa9a-5aae78aa05c3.png)

使用设备的开发者菜单启用远程 JS 调试

现在，通过点击下载的可执行文件打开`react-native-debugger`应用程序。如果没有任何反应，即使重新加载应用程序后仍然没有反应，那么问题肯定是由于设置了不同的端口：在菜单中，选择 Debugger，然后 New Window，选择端口 19001，一切都应该正常。当您启动应用程序时，它应该看起来像以下截图。请注意屏幕右侧的所有日志，左上角的第一个`Redux`操作，左下角的 React 工具（如果您不喜欢其中的某些工具，右键单击屏幕以隐藏其中的任何一个）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/58bf756b-f41f-4a72-b8d2-9c97f0f96783.png)

成功连接后，您将看到 react-native-debugger 中的三个工具同时运行

如果您检查网络选项卡，您会发现应用程序的 API 调用默认情况下不会显示。有一个简单的解决方法：右键单击`react-native-debugger`，选择启用网络检查，然后右键单击 Chrome 开发人员工具并选择 Log XMLHttpRequests，所有调用都将显示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/dc2d3c4a-f7e0-4d00-b545-d04b780a354e.png)

API 调用默认情况下不会显示，但可以通过右键单击 react-native-debugger 屏幕启用

您还可以检查`AsyncStorage`-请参阅以下屏幕截图。我选择隐藏`React`和`Redux DevTools`，就像我之前提到的那样，只是为了清晰。由于我们的应用实际上并没有使用`AsyncStorage`，我稍微捏造了一下：请注意，您可以对任何模块使用`require()`函数，然后直接使用它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/ee47bfc1-178f-47e8-9aac-9536ed3b0234.png)

使用 RN 调试器检查 AsyncStorage

还能说什么呢？实际上并不多，因为这些工具基本上与我们在 Web 上使用`React`时看到的工具相同。这里有趣的细节是，您可以一次获得所有这些工具，而不必处理许多单独的窗口。让我们通过考虑一个可能更喜欢的备用工具来结束这一章节。

# 使用 Reactotron 以另一种方式进行调试

虽然`react-native-debugger`可能适用于您大部分的需求，但还有另一个软件包，虽然与许多功能相符，但也添加了一些新功能，或者至少对旧功能进行了调整：Reactotron。这个工具也可以与纯`React`一起使用，但我选择在这里与 RN 一起显示它，因为您更有可能需要它。毕竟，Web 的`React`工具易于使用，而无需任何不必要的复杂性，而 RN 调试，正如我们所见，稍微有些挑战。据说 Reactotron 比`react-native-debugger`更有效，但我不会证明这一点：去试试看，并且要知道**结果可能有所不同**（**YMMV**）。让我们通过演示这种替代调试方式来结束这一章节。

# 准备工作

我们需要一对包：基本的 Reactotron 包，以及`reactotron-redux`来帮助处理 Redux。使用以下命令安装它们：

```js
npm install reactotron-react-native reactotron-redux --save-dev
```

Reactotron 可以与`redux-sagas`一起工作，而不是`redux-thunk`，甚至可以与 MobX 一起工作，而不是 Redux。在[`github.com/infinitered/reactotron`](https://github.com/infinitered/reactotron)上了解更多信息。

您还需要一个连接到您的应用程序的本机可执行工具。转到[`github.com/infinitered/reactotron/releases`](https://github.com/infinitered/reactotron/releases)的发布页面，并获取与您的环境匹配的软件包：在我特定的情况下，我只下载并解压了`Reactotron-linux-x64.zip`文件。对于 macOS 用户，还有另一种可能性：查看[`github.com/infinitered/reactotron/blob/master/docs/installing.md`](https://github.com/infinitered/reactotron/blob/master/docs/installing.md)。

安装所有这些后，我们准备好准备我们的应用程序；现在让我们这样做！

# 如何做...

事实上，您可以同时使用 Reactotron 和`react-native-debugger`，但为了避免混淆，让我们有一个单独的`App.reactotron.js`文件和一些其他更改。我们必须遵循一些简单的步骤。首先，让我们通过向`package.json`添加一个新的脚本来启用使用 Reactotron 运行我们的应用程序：

```js
    "scripts": {
        "start": "cp App.standard.js App.js && react-native-scripts start",
 "start-reactotron": "cp App.reactotron.js App.js && react-native-scripts start",
        .
        .
        .
```

其次，让我们配置连接和插件。我们将创建一个`reactotronConfig.js`文件来与`Reactotron`建立连接：

```js
// Source file: reactotronConfig.js

/* @flow */

import Reactotron from "reactotron-react-native";
import { reactotronRedux } from "reactotron-redux";

const reactotron = Reactotron.configure({
    port: 9090,
    host: "192.168.1.200"
})
    .useReactNative({
        networking: {
            ignoreUrls: /\/logs$/
        }
    })
    .use(
        reactotronRedux({
            isActionImportant: action => action.type.includes("success")
        })
    )
    .connect();

Reactotron.log("A knick-knack is a thing that sits on top of a whatnot");
Reactotron.warn("If you must make a noise, make it quietly");
Reactotron.error("Another nice mess you've gotten me into.");

export default reactotron;
```

以下是上一个代码片段中一些值和选项的一些细节：

+   `192.168.1.200`是我的机器的 IP，`9090`是建议使用的端口。

+   网络调试的`ignoreUrls`选项可以消除 Expo 发出的一些调用，但不会消除我们自己的代码，使会话更清晰。

+   `isActionImportant`函数允许您突出显示一些操作，以便它们更加显眼。在我们的情况下，我选择了`countries:success`和`regions:success`操作，这两个操作的类型都包含`"success"`，但当然，您也可以选择任何其他操作。

`Reactotron`还包括日志记录功能，因此我添加了三个（无用的！）调用，只是为了看看它们在我们的调试中是如何显示的。我不想展示我们添加的所有日志，但您可能希望使用以下命令，以便所有日志都会发送到`Reactotron`：

```js
console.log = Reactotron.log;
console.warn = Reactotron.warn;
console.error = Reactotron.error;
```

现在，我们必须调整我们的存储，以便它可以与`reactotron-redux`插件一起使用。我选择复制`store.js`，并将其命名为`store.reactotron.js`，并进行以下必要的更改：

```js
// Source file: src/regionsStyledApp/store.reactotron.js

/* @flow */

import { AsyncStorage } from "react-native";
import { applyMiddleware } from "redux";
import thunk from "redux-thunk";
import reactotron from "../../reactotronConfig";

import { reducer } from "./world.reducer";

export const store = reactotron.createStore(
    reducer,
    applyMiddleware(thunk)
);

// *continues*...
```

为了多样化，并且能够看到`Reactotron`如何处理`AsyncStorage`，我添加了一些（完全无用的！）行来设置一些项目：

```js
// ...*continued*

(async () => {
    try {
        await AsyncStorage.setItem("First", "Federico");
        await AsyncStorage.setItem("Last", "Kereki");
        await AsyncStorage.setItem("Date", "Sept.22nd");
        await AsyncStorage.getItem("Last");
    } catch (e) {
    }
})();
```

接下来，让我们对`App.js`文件进行一些更改。这些更改很小：只需包含配置文件，并使用我刚刚调整的存储：

```js
// Source file: App.reactotron.js

/* @flow */

import React from "react";
import { Provider } from "react-redux";

import "./reactotronConfig";
 import { store } from "./src/regionsStyledApp/store.reactotron";
import { ConnectedMain } from "./src/regionsStyledApp/main.connected";

export default class App extends React.PureComponent<> {
    render() {
        return (
            <Provider store={store}>
                <ConnectedMain />
            </Provider>
        );
    }
}
```

现在，我们准备好了；让我们看看它的运行情况！

有关`Reactotron`的完整文档，请查看开发者的网页[`github.com/infinitered/reactotron`](https://github.com/infinitered/reactotron)。`Reactotron`还包括更多插件，可以在使用`Redux`或`Storybook`时帮助您进行慢函数的基准测试，或记录消息，因此您可能会在那里找到许多有趣的东西。

# 它是如何工作的...

要使用`Reactotron`，只需启动它（双击应该就可以了），您将看到以下截图中显示的初始屏幕。该工具将等待您的应用连接；有时，可能需要多次尝试才能开始初始连接，但之后，事情应该会顺利进行。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/53889851-b482-4fab-81f1-b32dbc58e568.png)

Reactotron 的初始屏幕显示它正在等待连接

启动应用程序后，您将看到它已经建立了连接。`Reactotron`显示了一些详细信息：例如，设备正在运行 Android 8.1.0 版本，我们还可以看到设备的大小和比例。请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/67fd3435-06d3-4250-b1c4-3271e18a3e31.png)

连接成功后，您可以查看有关设备的详细信息

应用程序启动时，我们会得到类似以下截图的东西。请注意突出显示的操作（`countries:success`），ASYNC STORAGE 日志，以及我们添加的来自老电影的三行（对于电影爱好者来说，这是一个有趣的时间：谁说了这三句话？）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/6e2f9fe5-cab8-43b9-8185-fa74553a599a.png)

当我们的应用程序开始运行时，我们会在 Reactotron 窗口中得到所有这些调试文本。

我们还可以查看`Redux`存储的状态——请参阅以下截图。我检查了`deviceData`和一个国家：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/cef3163e-ae4e-443a-abcb-6290027d3776.png)

您可以检查 Redux 存储以查看其中放入了什么

最后，我在应用程序中选择了奥地利。我们可以检查已发出的 API 调用，以及随后分派的操作；请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/317cfaa2-af06-4c2b-97e0-41579c46d748.png)

在我们的应用程序中选择奥地利的结果：我们可以检查 API 调用和 Redux 操作。在这里，我们看到了

奥地利的九个地区，以及莫扎特故乡萨尔茨堡的详细信息

`Reactotron`有一些不同的功能，正如我们所说的，对于某些目的，它可能比`react-native-debugger`更适合您，因此它是您调试工具库中值得包含的内容。


# 第十三章：使用 Electron 创建桌面应用程序

我们将查看以下配方：

+   使用 React 设置 Electron

+   向您的应用程序添加 Node 功能

+   构建更窗口化的体验

+   测试和调试您的应用程序

+   制作一个可分发的软件包

# 介绍

在之前的章节中，我们使用`Node`来设置服务器，并使用`React`创建网页。在本章中，我们将把两者结合起来，添加另一个名为`Electron`的工具，并看看如何使用 JS 编写与任何本机可执行应用程序完全相同的桌面应用程序。

# 使用 React 设置 Electron

`Electron`是由 GitHub 创建的开源框架，它允许您开发桌面可执行文件，将 Node 和 Chrome 集成在一起，提供完整的 GUI 体验。 `Electron`已用于几个知名项目，包括开发人员工具，如 Visual Studio Code，Atom 和 Light Table。基本上，您可以使用 HTML，CSS 和 JS（或使用`React`，就像我们将要做的那样）来定义 UI，但您还可以使用`Node`中的所有软件包和功能，因此您不会受到沙箱化体验的限制，可以超越您只能使用浏览器做的事情。

您可能还想了解**渐进式 Web 应用程序**（**PWA**），这些是可以像本机应用程序一样“安装”在您的计算机上的 Web 应用程序。这些应用程序像其他应用程序一样启动，并在常见的应用程序窗口中运行，而不像浏览器那样显示标签或 URL 栏。 PWA 可能（尚未？）无法访问完整的桌面功能，但对于许多情况来说可能已经足够了。在[`developers.google.com/web/progressive-web-apps/`](https://developers.google.com/web/progressive-web-apps/)上阅读有关 PWA 的更多信息。

# 如何做...

现在，在这个配方中，让我们首先安装`Electron`，然后在后续的配方中，我们将看到如何将我们的一个`React`应用程序转换为桌面程序。

我从第八章的存储库副本开始，*扩展您的应用程序*，以获取国家和地区应用程序，这与我们用于 RN 示例的相同。恰好您可以完全使用 CRA 构建的应用程序与`Electron`完美地配合，甚至无需弹出它，这就是我们将在这里做的。首先，我们需要安装基本的`Electron`软件包，因此在我们编写`React`应用程序的同一目录中，我们将执行以下命令：

```js
npm install electron --save-dev
```

然后，我们需要一个启动 JS 文件。从[`github.com/electron/electron-quick-start`](https://github.com/electron/electron-quick-start)的`main.js`文件中获取一些提示，我们将创建以下`electron-start.js`文件：

```js
// Source file: electron-start.js

/* @flow */

const { app, BrowserWindow } = require("electron");

let mainWindow;

const createWindow = () => {
    mainWindow = new BrowserWindow({
        height: 768,
        width: 1024
    });
    mainWindow.loadURL("http://localhost:3000");
    mainWindow.on("closed", () => {
        mainWindow = null;
    });
};

app.on("ready", createWindow);

app.on("activate", () => mainWindow === null && createWindow());

app.on(
    "window-all-closed",
    () => process.platform !== "darwin" && app.quit()
);

```

以下是关于前面代码片段的一些要点：

+   此代码在`Node`中运行，因此我们使用`require()`而不是`import`。

+   `mainWindow`变量将指向浏览器实例，我们的代码将在其中运行

+   我们将首先运行我们的 React 应用程序，因此 Electron 将能够从[`localhost:3000`](http://localhost:3000)加载代码

在我们的代码中，我们还必须处理以下事件：

+   当`Electron`完成初始化并可以开始创建窗口时，将调用`"ready"`。

+   `"closed"`表示您的窗口已关闭；您的应用程序可能有多个窗口打开，因此在这一点上，您应该删除已关闭的窗口。

+   `"window-all-closed"`意味着您的整个应用程序已关闭。在 Windows 和 Linux 中，这意味着退出，但对于 macOS，通常不会退出应用程序，因为苹果通常的规则。

+   当您的应用程序重新激活时，将调用`"activate"`，因此如果窗口已被删除（如在 Windows 或 Linux 中），您必须重新创建它。

`Electron`可以发出的完整事件列表在[`github.com/electron/electron/blob/master/docs/api/app.md`](https://github.com/electron/electron/blob/master/docs/api/app.md)中；查看一下。

我们已经有了我们的`React`应用程序，所以我们只需要一种调用`Electron`的方法。将以下脚本添加到`package.json`中，你就准备好了：

```js
 "scripts": {
 "electron": "electron .",
        .
        .
        .
```

我们已经准备好了；让我们看看它是如何一起运作的。

# 它是如何工作的...

要以开发模式运行`Electron`应用程序（稍后我们将创建一个可执行文件），我们必须执行以下操作：

1.  从第四章运行我们的`restful_server_cors`服务器代码，*使用 Node 实现 RESTful 服务*。

1.  启动`React`应用程序，需要服务器正在运行。

1.  等待加载完成，然后再进行下一步。

1.  启动`Electron`。

因此，基本上，您将需要运行以下两个命令，但是您需要在单独的终端中执行这些命令，并且在启动`Electron`之前还需要等待`React`应用程序在浏览器中显示：

```js
// *in the directory for our restful server:* node out/restful_server_cors.js // *in the React app directory:* npm start

// *and after the React app is running, in other terminal:*
npm run electron
```

启动`Electron`后，屏幕迅速出现，我们再次发现我们的国家和地区应用程序，现在独立于浏览器运行。请参阅以下屏幕截图-请注意，我将窗口从其 1024×768 大小调整为：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d82abd1a-1bbf-4d4f-b534-22deedffeebc.png)

我们的应用程序作为一个独立的可执行文件运行

应用程序像往常一样工作；例如，我选择了一个国家，加拿大，并正确地得到了它的地区列表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/7a1a907c-f625-43ee-b7ee-827ed2d05df2.png)

应用程序像以前一样工作；选择一个国家，然后调用我们的 RESTful 服务器将获取其地区

我们完成了！您可以看到一切都是相互关联的，就像以前一样，如果您对`React`源代码进行任何更改，它们将立即反映在`Electron`应用程序中。

到目前为止，我们已经看到我们可以将网页制作成可执行文件；现在让我们看看如何使其更加强大。

# 向您的应用程序添加 Node 功能

在上一个教程中，我们看到只需进行一些小的配置更改，我们就可以将我们的网页变成一个应用程序。但是，您仍然受到限制，因为您仍然只能使用沙盒浏览器窗口中可用的功能。您不必这样想，因为您可以使用让您超越网络限制的功能来添加基本所有`Node`功能。让我们在本教程中看看如何做到这一点。

# 如何做...

我们想要为我们的应用程序添加一些典型桌面应用程序的功能。让我们看看如何做到这一点。向您的应用程序添加`Node`功能的关键是使用`Electron`中的`remote`模块。借助它，您的浏览器代码可以调用主进程的方法，从而获得额外的功能。

有关远程模块的更多信息，请参见[`github.com/electron/electron/blob/master/docs/api/remote.md`](https://github.com/electron/electron/blob/master/docs/api/remote.md)。还有一些额外的信息可能会在[`electronjs.org/docs/api/remote`](https://electronjs.org/docs/api/remote)中派上用场。

假设我们想要添加将国家地区列表保存到文件的可能性。我们需要访问`fs`模块以便能够写入文件，并且我们还需要打开对话框来选择要写入的文件。在我们的`serviceApi.js`文件中，我们将添加以下功能：

```js
// Source file: src/regionsApp/serviceApi.js

/* @flow */

const electron = window.require("electron").remote;

.
.
.

const fs = electron.require("fs");

export const writeFile = fs.writeFile.bind(fs);

export const showSaveDialog = electron.dialog.showSaveDialog;
```

添加了这个之后，我们现在可以从我们的主代码中写文件和显示对话框。要使用此功能，我们可以在我们的`world.actions.js`文件中添加一个新的操作：

```js
// Source file: src/regionsApp/world.actions.js

/* @flow */

import {
    getCountriesAPI,
    getRegionsAPI,
 showSaveDialog,
 writeFile
} from "./serviceApi";

.
.
.

export const saveRegionsToDisk = () => async (
    dispatch: ({}) => any,
    getState: () => { regions: [] }
) => {
    showSaveDialog((filename: string = "") => {
        if (filename) {
            writeFile(filename, JSON.stringify(getState().regions), e =>
                e && window.console.log(`ERROR SAVING ${filename}`, e);
            );
        }
    });
};
```

当调度`saveRegionsToDisk()`操作时，它将显示一个对话框，提示用户选择要写入的文件，然后将当前的地区集合（从`getState().regions`中获取）以 JSON 格式写入所选文件。我们只需向我们的`<RegionsTable>`组件添加适当的按钮，以便能够调度必要的操作：

```js
// Source file: src/regionsApp/regionsTableWithSave.component.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";

import "../general.css";

export class RegionsTable extends React.PureComponent<{
    loading: boolean,
    list: Array<{
        countryCode: string,
        regionCode: string,
        regionName: string
    }>,
 saveRegions: () => void
}> {
    static propTypes = {
        loading: PropTypes.bool.isRequired,
        list: PropTypes.arrayOf(PropTypes.object).isRequired,
 saveRegions: PropTypes.func.isRequired
    };

    static defaultProps = {
        list: []
    };

    render() {
        if (this.props.list.length === 0) {
            return <div className="bordered">No regions.</div>;
        } else {
            const ordered = [...this.props.list].sort(
                (a, b) => (a.regionName < b.regionName ? -1 : 1)
            );

            return (
                <div className="bordered">
                    {ordered.map(x => (
                        <div key={x.countryCode + "-" + x.regionCode}>
                            {x.regionName}
                        </div>
                    ))}
 <div>
 <button onClick={() => this.props.saveRegions()}>
 Save regions to disk
 </button>
 </div>
                </div>
            );
        }
    }
}
```

我们快要完成了！当我们将此组件连接到存储时，我们只需添加新的操作，如下所示：

```js
// Source file: src/regionsApp/regionsTableWithSave.connected.js

/* @flow */

import { connect } from "react-redux";

import { RegionsTable } from "./regionsTableWithSave.component";

import { saveRegionsToDisk } from "./world.actions";

const getProps = state => ({
    list: state.regions,
    loading: state.loadingRegions
});

const getDispatch = (dispatch: any) => ({
 saveRegions: () => dispatch(saveRegionsToDisk())
});

export const ConnectedRegionsTable = connect(
    getProps,
 getDispatch
)(RegionsTable);
```

现在，一切准备就绪-让我们看看它是如何工作的。

# 它是如何工作的...

我们添加的代码显示了我们如何访问`Node`包（在我们的情况下是`fs`）和一些额外的功能，比如显示一个保存到磁盘的对话框。（后一个功能与您的应用程序的本机外观更相关，我们将在即将到来的*构建更窗口化的体验*部分中看到更多相关内容。）当我们运行更新后的应用程序并选择一个国家时，我们将看到我们新添加的按钮，就像以下截图中的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d8572940-7b7d-43e5-8ee0-a80168759e00.png)

现在，在区域列表后面有一个“保存区域到磁盘”按钮

单击按钮将弹出对话框，允许您选择数据的目标：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d5ae729f-5ea2-44c1-a4d4-98046a461102.png)

单击按钮会弹出一个保存屏幕，指定要将结果保存到哪个文件

如果单击“保存”，区域列表将以 JSON 格式编写，就像我们在`writeRegionsToDisk()`函数中指定的那样：

```js
[{"countryCode":"CA","regionCode":"1","regionName":"Alberta"},
{"countryCode":"CA","regionCode":"10","regionName":"Quebec"},
{"countryCode":"CA","regionCode":"11","regionName":"Saskatchewan"},
{"countryCode":"CA","regionCode":"12","regionName":"Yukon"},
{"countryCode":"CA","regionCode":"13","regionName":"Northwest Territories"},
{"countryCode":"CA","regionCode":"14","regionName":"Nunavut"},
{"countryCode":"CA","regionCode":"2","regionName":"British Columbia"},
{"countryCode":"CA","regionCode":"3","regionName":"Manitoba"},
{"countryCode":"CA","regionCode":"4","regionName":"New Brunswick"},
{"countryCode":"CA","regionCode":"5","regionName":"Newfoundland and Labrador"},
{"countryCode":"CA","regionCode":"7","regionName":"Nova Scotia"},
{"countryCode":"CA","regionCode":"8","regionName":"Ontario"},
{"countryCode":"CA","regionCode":"9","regionName":"Prince Edward Island"}]
```

最后要注意的细节是，您的应用程序现在无法在浏览器中运行，您将不得不习惯看到以下截图中的内容，即使您的代码在`Electron`中运行良好：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/98c69b03-212c-4156-8085-84a9468a6f5a.png)

如果使用 Node 或 Electron 的功能，您的代码将不再在浏览器中运行，尽管它在 Electron 中的表现良好

就是这样！毫不费力地，我们能够超越普通浏览器应用的限制。您可以看到在`Electron`应用程序中几乎没有限制。

# 构建更窗口化的体验

在上一个示例中，我们添加了使用`Node`提供的任何和所有功能的可能性。在这个示例中，让我们专注于使我们的应用程序更像窗口，具有图标、菜单等。我们希望用户真的相信他们正在使用一个本地应用程序，具有他们习惯的所有功能。以下是来自[`electronjs.org/docs/api`](https://electronjs.org/docs/api)的有趣主题列表的一些亮点，但还有许多其他可用选项：

| `clipboard` | 使用系统剪贴板进行复制和粘贴操作 |
| --- | --- |
| `dialog` | 显示用于消息、警报、打开和保存文件等的本机系统对话框 |
| `globalShortcut` | 检测键盘快捷键 |
| `Menu`，`MenuItem` | 创建带有菜单和子菜单的菜单栏 |
| `Notification` | 添加桌面通知 |
| `powerMonitor`，`powerSaveBlocker` | 监控电源状态变化，并禁用进入睡眠模式 |
| `screen` | 获取有关屏幕、显示器等的信息 |
| `Tray` | 向系统托盘添加图标和上下文菜单 |

让我们添加一些这些功能，以便我们可以获得一个外观更好、更与桌面集成的应用程序。

# 如何做...

任何体面的应用程序可能至少应该有一个图标和一个菜单，可能还有一些键盘快捷键，所以让我们现在添加这些功能，并且仅仅是为了这个缘故，让我们也为区域写入磁盘时添加一些通知。连同我们已经使用的保存对话框，这意味着我们的应用程序将包括几个本机窗口功能。让我们实施以下步骤，并了解如何添加这些额外功能。

首先，让我们添加一个图标。显示图标是最简单的事情，因为在创建`BrowserWindow()`对象时只需要一个额外的选项。我不太擅长*图形视觉设计*，所以我只是从 Icon-Icons 网站上下载了 Alphabet, letter, r Icon Free 文件，网址是[`icon-icons.com/icon/alphabet-letter-r/62595`](https://icon-icons.com/icon/alphabet-letter-r/62595)。实现图标如下：

```js
mainWindow = new BrowserWindow({
    height: 768,
    width: 1024,
 icon: "./src/regionsApp/r_icon.png"
});
```

您还可以为系统托盘选择图标，尽管在该上下文中无法使用我们的区域应用程序，但您可能仍然希望了解一下。

在构建时，还有另一种方法可以向应用程序添加图标，即在`package.json`的``"build"``条目中添加额外的配置项。

接下来，我们将添加的第二个功能是一个菜单，还有一些全局快捷键。在我们的`App.regions.js`文件中，我们需要添加几行来访问`Menu`模块，并定义我们自己的菜单：

```js
// Source file: src/App.regions.js

.
.
.

import { getRegions } from "./regionsApp/world.actions";

.
.
.

const electron = window.require("electron").remote;
const { Menu } = electron;

const template = [
    {
        label: "Countries",
        submenu: [
            {
                label: "Uruguay",
                accelerator: "Alt+CommandOrControl+U",
                click: () => store.dispatch(getRegions("UY"))
            },
            {
                label: "Hungary",
                accelerator: "Alt+CommandOrControl+H",
                click: () => store.dispatch(getRegions("HU"))
            }
        ]
    },
    {
        label: "Bye!",
        role: "quit"
    }
];

const mainMenu = Menu.buildFromTemplate(template);
Menu.setApplicationMenu(mainMenu);
```

使用模板是创建菜单的一种简单方法，但您也可以手动执行，逐个添加项目。我决定有一个国家菜单，有两个选项，可以显示乌拉圭（我出生的地方）和匈牙利（我父亲的父亲来自的地方）的地区。`click`属性会分派适当的操作。我还使用`accelerator`属性来定义全局快捷键。请参阅[`github.com/electron/electron/blob/master/docs/api/accelerator.md`](https://github.com/electron/electron/blob/master/docs/api/accelerator.md)以获取可以使用的可能键组合的列表，包括以下内容：

+   *命令键*，如`Command`（或`Cmd`），`Control`（或`Ctrl`），或两者（`CommandOrControl`或`CmdOrCtrl`）

+   *备用键*，如`Alt`，`AltGr`或`Option`

+   *常用键*，如`Shift`，`Escape`（或`Esc`），`Tab`，`Backspace`，`Insert`或`Delete`

+   *功能键*，如`F1`到`F24`

+   光标键，包括`上`，`下`，`左`，`右`，`Home`，`End`，`PageUp`和`PageDown`

+   *媒体键*，如`MediaPlayPause`，`MediaStop`，`MediaNextTrack`，`MediaPreviousTrack`，`VolumeUp`，`VolumeDown`和`VolumeMute`

我还希望能够退出应用程序（不要紧，`Electron`创建的窗口已经有一个×图标来关闭它！）-这是一个预定义的*角色*，您不需要做任何特殊的事情。可以在[`electronjs.org/docs/api/menu-item#roles`](https://electronjs.org/docs/api/menu-item#roles)找到完整的角色列表。有了这些角色，您可以做很多事情，包括一些特定的 macOS 功能，以及以下内容：

+   使用剪贴板（`剪切`，`复制`，`粘贴`和`粘贴并匹配样式`）

+   处理窗口（`最小化`，`关闭`，`退出`，`重新加载`和`强制重新加载`）

+   缩放（`放大`，`缩小`和`重置缩放`）

最后，也只是为了这个缘故，让我们为文件写入时添加一个通知触发器。`Electron`有一个`Notification`模块，但我选择使用`node-notifier`，这个模块非常简单易用。首先，我们将以通常的方式添加这个包：

```js
npm install node-notifier --save
```

在`serviceApi.js`中，我们将不得不导出新的函数，这样我们就可以从其他地方导入，我们很快就会看到：

```js
const electron = window.require("electron").remote;

.
.
.

export const notifier = electron.require("node-notifier");
```

最后，让我们在我们的`world.actions.js`文件中使用它：

```js

import {
 notifier,
    .
    .
    .
} from "./serviceApi";
```

有了所有的设置，实际发送通知非常简单，需要的代码很少：

```js
// Source file: src/regionsApp/world.actions.js

.
.
.

export const saveRegionsToDisk = () => async (
    dispatch: ({}) => any,
    getState: () => { regions: [] }
) => {
    showSaveDialog((filename: string = "") => {
        if (filename) {
            writeFile(filename, JSON.stringify(getState().regions), e => {
 if (e) {
 window.console.log(`ERROR SAVING ${filename}`, e);
 } else {
 notifier.notify({
 title: "Regions app",
 message: `Regions saved to ${filename}`
 });
 }
            });
        }
    });
};
```

我们准备好了！让我们看看我们更*窗口化*的应用现在是什么样子。

# 工作原理...

首先，我们可以轻松检查图标是否出现。请参阅以下屏幕截图，并将其与本章的第一个屏幕截图进行比较：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/20c41f3f-3f44-4cfa-a477-2fa53e2a844e.png)

我们的应用现在有了自己的图标，可能不是太独特或原创，但总比没有好

现在，让我们看看菜单。它有我们的选项，包括快捷键：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/cdff7282-3cd4-426c-a3f8-f0826f616e04.png)

我们的应用现在也有一个菜单，就像任何值得尊敬的应用程序一样

然后，如果我们选择一个选项（比如乌拉圭），无论是用鼠标还是全局快捷键，屏幕都会正确加载预期的区域：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/0fcc9fda-b118-4eb9-8416-658f01cf18bb.png)

菜单项按预期工作；我们可以使用乌拉圭选项来查看我的国家的 19 个部门

最后，让我们看看通知是否按预期工作。如果我们点击“保存区域到磁盘”按钮并选择一个文件，我们将看到一个通知，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/95d43e2b-5b57-45fc-a614-26e9fe26c9fc.png)

现在保存文件会显示通知；在这种情况下，是为了 Linux 与 KDE

我们已经看到如何扩展我们的浏览器页面以包括`Node`功能和窗口本地函数。现在，让我们回到更基本的要求，学习如何测试和调试我们的代码。

# 测试和调试您的应用程序

现在，我们来到了一个常见的要求：测试和调试您的应用程序。我必须告诉您的第一件事是，关于测试方面没有什么新闻！我们为测试浏览器和`Node`代码所看到的所有技术仍然适用，因为您的`Electron`应用程序本质上只是一个浏览器应用程序（尽管可能具有一些额外功能），您将以与之前相同的方式模拟它，因此在这里没有新东西需要学习。

然而，就调试而言，由于您的代码不是在浏览器中运行，因此将会有一些新的要求。与`React Native`类似，我们将不得不使用一些工具，以便能够在代码运行时查看我们的代码。让我们在本节中看看如何处理所有这些。

# 如何做...

我们想要安装和配置所有必要的调试工具。让我们在本节中完成这些。调试的关键工具将是`electron-devtools-installer`，您可以从[`github.com/MarshallOfSound/electron-devtools-installer`](https://github.com/MarshallOfSound/electron-devtools-installer)获取。我们将使用一个简单的命令安装它，以及之前使用过的`Redux Devtools`扩展：

```js
npm install electron-devtools-installer redux-devtools-extension --save-dev
```

要使用`Redux Devtools`，我们将首先修复存储，就像我们之前做的那样；这里没有什么新东西：

```js
// Source file: src/regionsApp/store.with.redux.devtools.js

/* @flow */

import { createStore, applyMiddleware } from "redux";
import { composeWithDevTools } from "redux-devtools-extension";
import thunk from "redux-thunk";

import { reducer } from "./world.reducer";

export const store = createStore(
    reducer,
 composeWithDevTools(applyMiddleware(thunk))
);
```

对于工具本身，我们还需要稍微调整我们的起始代码：

```js
// Source file: electron-start.with.debugging.js

/* @flow */

const { app, BrowserWindow } = require("electron");
const {
 default: installExtension,
 REACT_DEVELOPER_TOOLS,
 REDUX_DEVTOOLS
} = require("electron-devtools-installer");

let mainWindow;

const createWindow = () => {
    mainWindow = new BrowserWindow({
        height: 768,
        width: 1024
    });
    mainWindow.loadURL("http://localhost:3000");

 mainWindow.webContents.openDevTools();

 installExtension(REACT_DEVELOPER_TOOLS)
 .then(name => console.log(`Added Extension: ${name}`))
 .catch(err => console.log("An error occurred: ", err));

 installExtension(REDUX_DEVTOOLS)
 .then(name => console.log(`Added Extension: ${name}`))
 .catch(err => console.log("An error occurred: ", err));

    mainWindow.on("closed", () => {
        mainWindow = null;
    });
};

app.on("ready", createWindow);

app.on("activate", () => mainWindow === null && createWindow());

app.on(
    "window-all-closed",
    () => process.platform !== "darwin" && app.quit()
);
```

好消息是，您可以从代码中添加所有工具，无需特殊安装或其他程序。进行这些简单的更改后，您就完成了；现在，让我们看看它的工作原理！

# 工作原理...

如果您启动修改后的代码，您将看到`Electron`窗口现在包括经典的 Chrome 工具，包括`React`和`Redux`。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/8f6658a1-4e0d-4ea0-81b4-def111922f9f.png)

electron-devtools-installer 包让您通过简单的程序添加所需的所有工具

除了控制台，您还可以使用`React Devtools`来检查组件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/db13bb2d-99c6-4601-9f08-6d07073d3f41.png)

React Devtools 可用于检查组件及其属性

同样，`Redux DevTools`让您检查操作和存储。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/ba5cb884-220b-4ea3-86f5-44d5615ca827.png)

您还安装了 Redux 开发者工具，可以让您检查与 Redux 相关的所有内容

正如您所看到的，我们已经习惯的所有工具都有了，只有一个例外——网络调用呢？让我们现在来看看。

# 还有更多...

您可能已经注意到，网络选项卡不显示应用程序发出的 API 调用。在 RN 中，我们解决了这个问题，因为我们使用的工具包括检查所有网络流量的功能，但在这里不会发生这种情况。因此，我们将不得不做一些额外的工作，而不是一个简单的自动化解决方案。如果您使用`axios`进行所有 API 调用，您可以简单地修改其原始方法以生成日志：

```js
// Source file: src/regionsApp/serviceApi.js

.
.
.

axios.originalGet = axios.get;
axios.get = (uri, options, ...args) =>
    axios.originalGet(uri, options, ...args).then(response => {
        console.log(`GET ${uri}`, {
            request: { uri, options, ...args },
            response
        });
        return response;
    });
```

所示的更改将导致每个成功的`GET`都记录您需要的所有内容，就像以下屏幕截图中所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/b31c2611-d73b-4458-b211-a0664279de46.png)

我们修改后的`axios.get()`方法产生了令人满意的日志

当然，这只是所需更改的冰山一角。您将不得不为失败的调用添加代码（因此，在`.catch()`中添加一些日志），您还将希望对其他方法（`.post()`、`.delete()`等）进行此类更改，但必要的代码很简单，所以我将把它作为读者的练习留下！

# 制作可分发的软件包

现在我们有了一个完整的应用程序，剩下的就是将其打包，以便您可以将其作为可执行文件交付给 Windows、Linux 或 macOS 用户。让我们通过本节来看看如何做到这一点。

# 如何做...

有许多打包应用程序的方法，但我们将使用一个名为`electron-builder`的工具，如果您能正确配置它，将使这一切变得更加容易！

您可以在[`www.electron.build/`](https://www.electron.build/)上阅读有关`electron-builder`、其功能和配置的更多信息。

让我们看看必要的步骤。首先，我们将不得不开始定义构建配置，我们的初始步骤将是，像往常一样，安装工具：

```js
npm install electron-builder --save-dev
```

要访问添加的工具，我们需要一个新的脚本，我们将在`package.json`中添加：

```js
"scripts": {
 "dist": "electron-builder",
    .
    .
    .
}
```

我们还需要向`package.json`添加一些更多的细节，这些细节对于构建过程和生成的应用程序是必需的。特别是，需要更改`homepage`，因为 CRA 创建的`index.html`文件使用绝对路径，这些路径将无法与`Electron`后来一起使用：

```js
"name": "chapter13",
"version": "0.1.0",
"description": "Regions app for chapter 13",
"homepage": "./",
"license": "free",
"author": "Federico Kereki",
```

最后，将需要一些特定的构建配置。您不能在 Linux 或 Windows 机器上构建 macOS，因此我将不包括该配置。我们必须指定文件的位置，要使用的压缩方法等等：

```js
"build": {
    "appId": "com.electron.chapter13",
    "compression": "normal",
    "asar": true,
    "extends": null,
    "files": [
        "electron-start.js",
        "build/**/*",
        "node_modules/**/*",
        "src/regionsApp/r_icon.png"
    ],
    "linux": {
        "target": "zip"
    },
    "win": {
        "target": "portable"
    }
}
```

在[`www.electron.build/multi-platform-build`](https://www.electron.build/multi-platform-build)上阅读有关为不同平台构建的更多信息。有关所有配置选项的更多信息，请参阅[`www.electron.build/configuration/configuration#configuration`](https://www.electron.build/configuration/configuration#configuration)。

我们已经完成了所需的配置，但代码本身也需要做一些更改，我们将不得不调整代码以构建包。当打包的应用程序运行时，将不会有 webpack 服务器运行；代码将从构建的`React`包中获取。此外，您不希望包含调试工具。因此，起始代码将需要以下更改：

```js
// Source file: electron-start.for.builder.js

/* @flow */

const { app, BrowserWindow } = require("electron");
const path = require("path");
const url = require("url");

let mainWindow;

const createWindow = () => {
    mainWindow = new BrowserWindow({
        height: 768,
        width: 1024,
 icon: path.join(__dirname, "./build/r_icon.png")
    });
    mainWindow.loadURL(
 url.format({
 pathname: path.join(__dirname, "./build/index.html"),
 protocol: "file",
 slashes: true
 })
    );
    mainWindow.on("closed", () => {
        mainWindow = null;
    });
};

app.on("ready", createWindow);

app.on("activate", () => mainWindow === null && createWindow());

app.on(
    "window-all-closed",
    () => process.platform !== "darwin" && app.quit()
);
```

主要是，我们正在从`build/`目录中获取图标和代码。`npm run build`命令将负责生成该目录，因此我们可以继续创建我们的可执行应用程序。

# 它是如何工作的...

完成此设置后，构建应用程序基本上是微不足道的。只需执行以下操作，所有可分发文件将在`dist/`目录中找到：

```js
npm run electron-builder
```

您可能希望在`.gitignore`文件中添加一行，以便不提交分发目录。我在我的文件中包含了`**/dist`行，与之前的`**/node_modules`和`**/dist`现有行相对应。

现在我们有了 Linux 应用程序，我们可以通过解压`.zip`文件并单击`chapter13`可执行文件来运行它。（名称来自`package.json`中的``"name"``属性，我们之前修改过。）结果应该像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/0d4b11ce-77df-40c5-81c9-7a860b8375c4.png)

Linux 可执行文件作为本机应用程序运行，显示与我们之前看到的相同的屏幕。

我还想尝试一下 Windows 的`EXE`文件。由于我没有 Windows 机器，我通过从[`developer.microsoft.com/en-us/microsoft-edge/tools/vms/`](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)下载免费的`VirtualBox`虚拟机来实现，它们只能使用 90 天，但我只需要几分钟。

下载虚拟机，将其设置在`VirtualBox`中，并最终运行它后，产生的结果与 Linux 的结果相同，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/c2ccbf1b-74d5-430b-a6f3-d88513be4cf8.png)

我们的本机 Windows 应用程序在 Windows 机器上同样运行

因此，我们已经成功开发了一个`React`应用程序，增强了`Node`和`Electron`功能，并最终为不同的操作系统打包了它。有了这个，我们就完成了！


# 第十四章：其他您可能喜欢的书籍

如果您喜欢这本书，您可能会对 Packt 的其他书感兴趣：

![](https://www.packtpub.com/web-development/building-enterprise-javascript-applications)

**构建企业级 JavaScript 应用程序**

丹尼尔·李

ISBN：9781788477321

+   在整本书中实践测试驱动开发（TDD）

+   使用黄瓜、Mocha 和 Selenium 编写端到端、集成、单元和 UI 测试

+   使用 Express 和 Elasticsearch 构建无状态 API

+   使用 OpenAPI 和 Swagger 记录您的 API

+   使用 React、Redux 和 Webpack 构建和捆绑前端应用程序

+   使用 Docker 容器化服务

+   使用 Kubernetes 部署可扩展的微服务

![](https://www.packtpub.com/web-development/learn-blockchain-programming-javascript)

**使用 JavaScript 学习区块链编程**

埃里克·特劳布

ISBN：9781789618822

+   深入了解区块链和环境设置

+   从头开始创建您自己的去中心化区块链网络

+   构建和测试创建去中心化网络所需的各种端点

+   了解工作证明和用于保护数据的哈希算法

+   挖掘新的区块，创建新的交易，并将交易存储在区块中

+   探索共识算法并将其用于同步区块链网络

# 留下评论-让其他读者知道您的想法

请通过在购买书籍的网站上留下评论与其他人分享您对这本书的想法。如果您从亚马逊购买了这本书，请在该书的亚马逊页面上留下诚实的评论。这对其他潜在读者来说非常重要，他们可以看到并使用您的公正意见来做出购买决定，我们可以了解我们的客户对我们的产品的看法，我们的作者可以看到您与 Packt 合作创建的标题的反馈。这只需要您几分钟的时间，但对其他潜在客户、我们的作者和 Packt 都是有价值的。谢谢！
