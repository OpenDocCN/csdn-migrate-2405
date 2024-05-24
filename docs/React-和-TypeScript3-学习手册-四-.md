# React 和 TypeScript3 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487`](https://zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：组件模式

在本章中，我们将继续构建之前的 React 商店。我们将构建一个可重用的选项卡组件，以及一个可重用的加载指示器组件，两者都将在商店的产品页面上使用。本章将首先将产品页面分割为容器和展示组件，然后再处理选项卡组件，利用复合组件和渲染属性模式。然后，我们将继续实现一个使用高阶组件模式的加载指示器组件。

在这一章中，我们将学习以下主题：

+   容器和展示组件

+   复合组件

+   渲染属性模式

+   高阶组件

# 技术要求

在本章中，我们将使用以下技术：

+   **Node.js 和** `npm`：TypeScript 和 React 依赖于这些。我们可以从[`nodejs.org/en/download/`](https://nodejs.org/en/download/)安装这些。如果我们已经安装了这些，确保`npm`至少是 5.2 版本。

+   **Visual Studio Code**：我们需要一个编辑器来编写 React 和 TypeScript 代码，可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)安装。我们还需要在 Visual Studio Code 中安装 TSLint（由 egamma 提供）和 Prettier（由 Estben Petersen 提供）扩展。

+   **React 商店**：我们将从我们在查看 React Router 的章节中开始的项目开始。这可以在 GitHub 上找到：[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/04-ReactRouter`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/04-ReactRouter)。

本章中的所有代码片段都可以在以下网址找到：[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/06-ComponentPatterns`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/06-ComponentPatterns)。

# 容器和展示组件

将页面分割为容器和展示组件可以使展示组件更容易重用。容器组件负责事物的运作，从 Web API 获取数据并管理状态。展示组件负责外观。展示组件通过属性接收数据，同时具有属性事件处理程序，以便其容器可以管理用户交互。

我们将在我们的 React 商店中使用这种模式，将产品页面分成容器和展示组件。`ProductPage`组件将是容器，我们将引入一个名为`Product`的新组件，它将是展示组件：

1.  让我们首先在 Visual Studio Code 中打开我们的商店项目，并在终端中输入以下命令来启动应用程序：

```jsx
npm start
```

1.  如果我们导航到一个产品，让我们回顾一下产品页面是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/fe7f8f05-1de1-488a-a184-9faace7ade77.png)

1.  让我们创建一个名为`Product.tsx`的新文件，其中包含我们的展示组件，内容如下：

```jsx
import * as React from "react";

const Product: React.SFC<{}> = props => {
  return <React.Fragment>TODO</React.Fragment>;
};

export default Product;
```

我们的展示组件是一个函数组件。

1.  展示组件通过 props 接收数据，也通过 props 委托事件处理。因此，让我们为产品数据项、是否已添加到购物篮以及添加到购物篮的处理程序创建 props：

```jsx
import * as React from "react";
import { IProduct } from "./ProductsData";

interface IProps {
 product: IProduct;
 inBasket: boolean;
 onAddToBasket: () => void;
}
const Product: React.SFC<IProps> = props => {
  return <React.Fragment>TODO</React.Fragment>;
};

export default Product;
```

1.  如果我们查看`ProductsPage.tsx`，我们将复制`React.Fragment`部分中有产品时的 JSX。然后我们将其粘贴到`Product`组件的 return 语句中：

```jsx
const Product: React.SFC<IProps> = props => {
  return (
    <React.Fragment>
 <h1>{product.name}</h1>
 <p>{product.description}</p>
 <p className="product-price">
 {new Intl.NumberFormat("en-US", {
 currency: "USD",
 style: "currency"
 }).format(product.price)}
 </p>
 {!this.state.added && (
 <button onClick={this.handleAddClick}>Add to basket</button>
 )}
 </React.Fragment>
  );
};
```

我们现在有一些参考问题需要解决。

1.  让我们在 return 语句之前定义一个产品变量，以解决 JSX 中产品引用的问题：

```jsx
const product = props.product;
return ( 
  ...
)
```

1.  现在通过`inBasket` prop 传递产品是否在购物篮中。因此，让我们改变添加到购物篮按钮周围的条件以使用这个 prop：

```jsx
{!props.inBasket && (
  <button onClick={this.handleAddClick}>Add to basket</button>
)}
```

1.  我们需要解决的最后一个参考问题是点击“添加到购物篮”按钮的处理程序。让我们首先创建一个简单调用`onAddToBasket` prop 的处理程序：

```jsx
const product = props.product;

const handleAddClick = () => {
 props.onAddToBasket();
};

return (
  ...
);
```

1.  我们可以在 JSX 中删除对此处理程序的引用`this`。

```jsx
{!props.inBasket && (
  <button onClick={handleAddClick}>Add to basket</button>
)}
```

这就是我们目前的`Product`展示组件完成了。因此，让我们在`ProductPage`组件中引用我们的`Product`组件。

1.  首先，让我们将我们的`Product`组件导入到`ProductPage.tsx`中：

```jsx
import Product from "./Product";
```

1.  现在，让我们用我们的`Product`组件替换在 JSX 中复制的部分：

```jsx
return (
 <div className="page-container">
   <Prompt when={!this.state.added} message={this.navAwayMessage} />
   {product ? (
     <Product
 product={product}
 inBasket={this.state.added}
 onAddToBasket={this.handleAddClick}
 />
   ) : (<p>Product not found!</p>)}
 </div>
);
```

我们将产品、产品是否已添加到购物篮以及添加到购物篮的处理程序一起作为 props 传递给`Product`组件。

如果我们再次查看商店并转到产品页面，它看起来完全一样。

因此，我们刚刚实现了我们的第一个容器和展示组件。容器组件非常适合作为页面中的顶层组件，从 Web API 获取数据，并管理页面内的所有状态。展示组件只关注需要呈现在屏幕上的内容。这种模式的好处是展示组件可以更容易地在应用程序的其他地方使用。例如，我们的`Product`组件可以相当容易地在商店中创建的其他页面上使用。这种模式的另一个好处是，展示组件通常更容易进行单元测试。在我们的示例中，我们的`Product`组件是一个纯函数，因此对其进行单元测试只是检查不同输入的输出是否正确，因为没有副作用。我们将在本书的后面详细介绍单元测试。

在下一节中，我们将继续增强我们的产品页面，通过向其添加评论并添加选项卡来将产品描述与评论分开。

# 复合组件

复合组件是一组共同工作的组件。我们将使用这种模式在产品页面上创建一个可重用的选项卡组件，以分隔产品描述和评论。

# 为产品添加评论

在创建我们的`Tabs`复合组件之前，让我们在产品页面上添加评论：

1.  首先，我们需要在`ProductsData.ts`中为评论数据结构添加一个接口：

```jsx
export interface IReview {
  comment: string;
  reviewer: string;
}
```

1.  我们现在可以将评论添加到我们的产品接口中：

```jsx
export interface IProduct {
  ...
  reviews: IReview[];
}
```

1.  我们现在可以将评论添加到我们的产品数据数组中：

```jsx
const products: IProduct[] = [
  {
    id: 1,
    ...
    reviews: [
 {
 comment: "Excellent! This does everything I want",
 reviewer: "Billy"
 },
 { comment: "The best router I've ever worked with", reviewer: 
      "Sally" }
 ]
  },
  {
    id: 2,
    ..
    reviews: [
 {
 comment: "I've found this really useful in a large app I'm 
        working on",
 reviewer: "Billy"
 },
 {
 comment: "A bit confusing at first but simple when you get   
        used to it",
 reviewer: "Sally"
 }
 ]
  },
  {
    id: 3,
    ..
    reviews: [
 {
 comment: "I'll never work with a REST API again!",
 reviewer: "Billy"
 },
 {
 comment: "It makes working with GraphQL backends a breeze",
 reviewer: "Sally"
 }
 ]
  }
];
```

因此，我们为每个产品添加了一个`reviews`属性，它是一个评论数组。每个评论都是一个包含`comment`和`reviewer`属性的对象，由`IReview`接口定义。

1.  有了我们的数据，让我们在描述之后将评论添加到我们的`Product`组件中：

```jsx
<p>{product.description}</p>
<div>
 <ul className="product-reviews">
 {product.reviews.map(review => (
 <li key={review.reviewer} className="product-reviews-item">
 <i>"{review.comment}"</i> - {review.reviewer}
 </li>
 ))}
 </ul>
</div>
<p className="product-price">
  ...
</p>
```

因此，我们正在使用`map`函数在`reviews`数组上显示`comment`和`reviewer`。

1.  我们引用了一些新的 CSS 类，因此让我们将它们添加到`index.css`中：

```jsx
.product-reviews {
  list-style: none;
  padding: 0px;
}
.product-reviews .product-reviews-item {
  display: block;
  padding: 8px 0px;
}
```

如果我们查看正在运行的应用程序并转到产品，我们现在将看到评论：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/d72a2bb2-abca-46ce-a62a-c3b1c78c5741.png)

现在我们已经添加了评论，我们可以在下一节中处理我们的`Tabs`组件。

# 创建一个基本的选项卡组件

我们的工作现在是使用我们将要构建的选项卡组件将描述与评论分开。我们将首先创建一个简单的选项卡组件，然后在下一节将其重构为复合组件模式。

是时候开始我们的选项卡组件了：

1.  首先，让我们创建一个名为`Tabs.tsx`的文件，用以下内容作为骨架类组件：

```jsx
import * as React from "react";

interface IProps {}
interface IState {}
class Tabs extends React.Component<IProps, IState> {
  public constructor(props: IProps) {
    super(props);
    this.state = {};
  }
  public render() {
    return;
  }
}

export default Tabs;
```

我们选择创建基于类的组件，因为我们的组件将需要跟踪活动的选项卡标题的状态。

1.  因此，让我们通过添加一个属性来完成我们状态的接口，该属性将给出活动的标题名称：

```jsx
interface IState {
  activeHeading: string;
}
```

1.  我们的组件将接受选项卡标题并将它们显示为属性。因此，让我们完成这个接口：

```jsx
interface IProps {
  headings: string[];
}
```

因此，我们的组件可以接受一个`headings`属性中的标题名称数组。

1.  让我们现在在构造函数中为`activeHeading`状态创建初始值：

```jsx
public constructor(props: IProps) {
  super(props);
  this.state = {
    activeHeading:
 this.props.headings && this.props.headings.length > 0
 ? this.props.headings[0]
 : ""
  };
}
```

因此，活动标题最初将设置为`headings`数组中的第一个元素。三元运算符确保我们的组件在消费者未传递任何选项卡时不会产生错误。

1.  现在转到渲染方法，让我们通过映射`headings`属性在列表中渲染我们的选项卡：

```jsx
    public render() {
      return (
        <ul className="tabs">
          {this.props.headings.map(heading => (
            <li className={heading === this.state.activeHeading ? 
            "active" : ""}
            >
              {heading}
            </li>
          ))}
        </ul>
      );
    }
```

我们引用了一些 CSS 类，包括`active`，它是基于三元运算符设置的，取决于正在呈现的是否是活动选项卡标题。

1.  现在让我们将这些 CSS 类添加到`index.css`中：

```jsx
.tabs {
  list-style: none;
  padding: 0;
}
.tabs li {
  display: inline-block;
  padding: 5px;
  margin: 0px 5px 0px 5px;
  cursor: pointer;
}
.tabs li:focus {
  outline: none;
}
.tabs li.active {
  border-bottom: #222 solid 2px;
}
```

在我们可以看到我们的选项卡组件是什么样子之前，我们需要使用它。

1.  因此，让我们首先导入`Tabs`组件，然后将其添加到`Product`组件中。

```jsx
import Tabs from "./Tabs";
```

1.  现在我们可以在产品名称和描述之间添加`Tabs`组件：

```jsx
<h1>{product.name}</h1>
<Tabs headings={["Description", "Reviews"]} />
<p>{product.description}</p>
```

我们将向`Tabs`组件传递我们要显示的两个选项卡标题，即描述和评论。

让我们看看这是什么样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/2224eb38-ef28-4945-9ee0-e297c2a8a6e1.png)

这是一个良好的开始。第一个选项卡下划线是`active` CSS 样式，正如我们所希望的那样。但是，如果我们点击评论选项卡，什么也不会发生。

1.  因此，让我们在`Tabs.tsx`中引用点击处理程序来处理每个选项卡：

```jsx
<li
  onClick={this.handleTabClick}
  className={heading === this.state.activeHeading ? "active" : ""}
>
  {heading}
</li>
```

1.  现在让我们也实现点击处理程序：

```jsx
private handleTabClick = (e: React.MouseEvent<HTMLLIElement>) => {
  const li = e.target as HTMLLIElement;
  const heading: string = li.textContent ? li.textContent : "";
  this.setState({ activeHeading: heading });
};
```

我们首先从`li`的`textContent`中提取标题。然后将`activeHeading`状态设置为此标题。这将导致 React 重新渲染组件，显示所点击的选项卡为活动状态。

请注意，我们使用`as`关键字帮助 TypeScript 编译器将`li`变量声明为`HTMLLIElement`。如果不这样做，编译器将不允许我们访问其中的`textContent`属性。

如果我们再次转到运行的应用程序，现在我们可以单击选项卡并看到活动状态的变化。

目前，我们的选项卡组件只是渲染一些可以单击的选项卡。它还没有与任何内容相关联。直到下一节关于渲染属性模式的部分，我们才会将标题与内容关联起来。但是，现在是时候探索复合组件模式，并在下一节中稍微增强我们的选项卡标题。

# 利用复合组件模式

目前，我们的选项卡标题只能是字符串。如果我们希望允许组件的使用者在标题中定义更丰富的内容怎么办？例如，使用者可能希望在选项卡标题前放置图标或使标题加粗。因此，使用的 JSX 可能如下所示：

```jsx
<Tabs>
  <Tabs.Tab name="Description" initialActive={true}>
    <b>Description</b>
  </Tabs.Tab>
  <Tabs.Tab name="Reviews">
     Reviews
  </Tabs.Tab>
</Tabs>
```

在上一个示例中，`Tabs`和`Tabs.Tab`是复合组件：

+   `Tabs`是渲染其中的`Tabs.Tab`组件的组件。它还管理活动选项卡的状态。

+   `Tabs.Tab`渲染单个标题。它以唯一的选项卡名称作为属性，允许管理活动选项卡。它还接受一个名为`initialActive`的`boolean`属性，该属性在首次加载时设置该选项卡为活动状态。渲染的标题是`Tabs.Tab`标记内的内容。因此，第一个选项卡将以粗体呈现描述。

因此，让我们将我们的基本选项卡组件重构为一个复合组件，可以类似于上一个示例中使用：

1.  我们的`Tabs`组件不再接受任何属性，因此，让我们删除`IProps`接口。我们可以删除构造函数，因为我们不再需要从属性初始化状态。我们还将状态属性的名称从`activeHeading`更改为`activeName`：

```jsx
interface IState {
  activeName: string;
}
class Tabs extends React.Component<{}, IState> {
  public render() {
    ...
  }
  ...
}
```

1.  首先，我们将在`Tabs`中工作`Tab`组件。因此，让我们为其属性创建一个接口：

```jsx
interface ITabProps {
  name: string;
  initialActive?: boolean;
}
```

+   `name`属性是选项卡的唯一名称。稍后将使用它来帮助我们管理活动选项卡。

+   `initialActive`属性指定组件首次加载时选项卡是否处于活动状态。

1.  现在让我们在我们的`Tabs`类组件中添加以下`Tab`函数组件：

```jsx
class Tabs extends React.Component<IProps, IState> {

  public static Tab: React.SFC<ITabProps> = props => <li>TODO - render the nodes child nodes</li>;

  public render() {...}

  ...
}
```

这是将渲染每个标签的组件的开始。`Tab`组件被定义为`Tabs`组件的静态属性。这意味着`Tab`存在于实际的`Tabs`类中，而不是它的实例中。因此，我们必须记住我们无法访问任何`Tabs`实例成员（例如`this`）。但是，现在我们可以在 JSX 中使用`Tabs.Tab`来引用`Tab`，这是我们的要求之一。

目前，`Tab`只是渲染带有提醒的`li`，提醒我们需要以某种方式渲染组件的子节点。请记住，我们希望消费`Tabs`组件的标记如下：

```jsx
<Tabs.Tab name="Description" initialActive={true}>
  <b>Description</b>
/Tabs.Tab>
```

1.  因此，我们的渲染函数需要以某种方式在我们的`li`标签内渲染`<b> Description </b>`。我们该如何做呢？答案是通过一个叫做`children`的特殊属性：

```jsx
public static Tab: React.SFC<ITabProps> = props => <li>{props.children}</li>;
```

React 组件属性可以是任何类型，包括 React 节点。`children`属性是 React 给组件的一个特殊属性，其中包含组件的子节点。我们通过在 JSX 中引用`children`属性来渲染组件的子节点。

我们的`Tab`组件还没有完成，但我们暂时会保持这样。现在我们需要继续进行`Tabs`组件。

1.  `Tabs`类中的`render`方法现在只是简单地渲染其子节点。让我们用以下内容替换这个方法：

```jsx
public render() {
  return (
    <ul className="tabs">{this.props.children}</ul>
  );
}
```

我们再次使用神奇的`children`属性来渲染`Tabs`中的子节点。

我们在复合`Tabs`和`Tab`组件中取得了进展，但是我们的项目不再编译，因为我们有一个标签点击处理程序`handleTabClick`，它不再被引用。当点击标签标题时，我们需要以某种方式从`Tab`组件中引用它，但请记住`Tab`无法访问`Tabs`的成员。那么，我们该如何做呢？我们将在下一节中找到这个问题的答案。

# 使用 React 上下文共享状态

React 上下文允许在组件之间共享状态。它与复合组件非常配合。我们将在`Tabs`和`Tab`组件中使用它来共享状态：

1.  我们的第一个任务是在文件顶部创建一个用于`Tabs.tsx`中使用的上下文接口，就在导入语句的下面：

```jsx
interface ITabsContext {
  activeName?: string;
  handleTabClick?: (name: string) => void;
}
```

因此，我们的上下文将包含活动标签名称以及标签点击处理程序的引用。这些是需要在组件之间共享的两个状态。

1.  接下来，让我们在`ITabsContext`接口下创建上下文：

```jsx
const TabsContext = React.createContext<ITabsContext>({});
```

我们在 React 中使用`createContext`函数创建了我们的上下文，这是一个通用函数，用于创建一个通用类型的上下文，在我们的情况下是`ITabsContext`。

我们需要将默认上下文值作为参数值传递给`createContext`，但在我们的情况下这是没有意义的，所以我们只是传递一个空的`{}`对象，以使 TypeScript 编译器满意。这就是为什么`ITabsContext`中的两个属性都是可选的。

1.  现在是时候在我们的复合组件中使用这个上下文了。我们需要做的第一件事是在`Tabs`的`render`方法中定义上下文提供程序：

```jsx
public render() {
  return (
    <TabsContext.Provider
 value={{
 activeName: this.state ? this.state.activeName : "",
 handleTabClick: this.handleTabClick
 }}
 >
      <ul className="tabs">{this.props.children}</ul>
    </TabsContext.Provider>
  );
}
```

这里有一些事情要处理，所以让我们来分解一下：

+   我们之前声明的上下文常量`TabsContext`在 JSX 中可以作为`<TabsContext />`组件使用。

+   上下文提供程序用值填充上下文。鉴于`Tabs`管理状态和事件处理，将提供程序引用到那里是有意义的。

+   我们使用`<TabsContext.Provider />`引用提供程序。

+   提供程序接受一个名为`value`的属性作为上下文值。我们将其设置为一个包含活动选项卡名称和选项卡点击事件处理程序的对象。

1.  我们需要稍微调整选项卡点击处理程序，因为点击不再直接在`Tabs`中处理。因此，我们只需要将活动选项卡名称作为参数传入，然后在方法中设置活动选项卡名称状态：

```jsx
private handleTabClick = (name: string) => {
  this.setState({ activeName: name });
};
```

1.  现在我们已经向上下文提供了一些数据，是时候在`Tab`组件中使用它了：

```jsx
 public static Tab: React.SFC<ITabProps> = props => (
  <TabsContext.Consumer>
 {(context: ITabsContext) => {
 const activeName = context.activeName
 ? context.activeName
 : props.initialActive
 ? props.name
 : "";
 const handleTabClick = (e: React.MouseEvent<HTMLLIElement>) => 
      {
 if (context.handleTabClick) {
 context.handleTabClick(props.name);
 }
 };
      return (
        <li
          onClick={handleTabClick}
 className={props.name === activeName ? "active" : ""}
        >
          {props.children}
        </li>
      );
    }}
  </TabsContext.Consumer>
);
```

这看起来又有点令人生畏，所以让我们来分解一下：

+   我们可以通过上下文组件内的`Consumer`组件来消费上下文。所以，在我们的情况下是`<TabsContext.Consumer />`。

+   `Consumer`的子代需要是一个具有上下文值参数并返回一些 JSX 的函数。`Consumer`然后将渲染我们返回的 JSX。

如果这仍然有点令人困惑，不要担心。当我们讨论子代属性和渲染属性时，我们将在以后更详细地介绍这种模式。

+   这个上下文函数为我们提供了渲染选项卡所需的一切。我们可以从`context`参数中访问状态，还可以访问`Tab`组件的`props`对象。

+   函数的第一行通过使用上下文中的内容来确定活动选项卡名称。如果上下文中的活动选项卡是空字符串，我们将使用当前选项卡名称，如果已经定义为初始活动选项卡。

+   函数的第二行创建了一个标签点击处理程序，如果已经指定了上下文标签点击处理程序，则调用它。

+   返回语句与以前一样，但我们已经能够添加标签点击处理程序的引用和类名。

所以，这就是我们的标签复合组件。React 上下文的语法一开始可能看起来有点奇怪，但当你习惯了它之后，它真的很简单和优雅。

在我们尝试之前，我们需要在我们的`Product`组件中使用我们的复合组件。让我们用以下突出显示的 JSX 替换我们之前对`Tabs`组件的使用：

```jsx
 <React.Fragment>
  <h1>{product.name}</h1>

  <Tabs>
 <Tabs.Tab name="Description" initialActive={true}>
 <b>Description</b>
 </Tabs.Tab>
 <Tabs.Tab name="Reviews">Reviews</Tabs.Tab>
 </Tabs>

  <p>{product.description}</p>
  ...
</React.Fragment>
```

这正是我们在开始构建复合标签组件时想要实现的 JSX。如果我们转到运行的应用程序并浏览到产品页面，我们的标签组件将完美地工作，描述标签会以粗体显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/2cb6cee1-2be4-4f5b-b4a2-d71dbe9bf45d.png)

因此，复合组件非常适合相互依赖的组件。`<Tabs.Tab />`的语法真的*强调了*`Tab`需要与`Tabs`一起使用。

React 上下文与复合组件非常配合，允许复合中的组件轻松共享状态。状态甚至可以包括诸如事件处理程序之类的函数。

允许消费者指定要在组件的各个部分中呈现的内容，为消费者提供了极大的灵活性。将此自定义内容指定为组件的子级是直观且自然的。在接下来的部分中，我们将继续使用这种方法来完成我们的标签组件。

# 渲染道具模式

在上一节中，我们使用了渲染道具模式的一种形式，其中我们利用了`children`道具。我们用它来允许`Tab`组件的消费者为标签标题呈现自定义内容。这很好，但是如果我们想允许消费者在组件的不同部分呈现自定义内容怎么办？在我们的`Tabs`组件中，我们还没有允许消费者呈现标签的内容。我们确实希望消费者能够为此指定自定义内容，但是既然我们已经使用了`children`道具来表示标题，那么现在该怎么做呢？

答案很简单，但一开始并不明显。答案是，因为 props 可以是任何东西，它们可以是一个呈现内容的函数 - 就像特殊的`children`prop 一样。这些类型的 prop 被称为渲染 prop。我们可以拥有尽可能多的渲染 prop，从而灵活地允许消费者呈现组件的多个部分。

在上一节中，当我们使用 React 上下文时，实际上使用了渲染 prop。我们消费上下文的方式是通过渲染 prop。

接下来，我们将利用渲染 prop 模式完成我们的`Tabs`组件。

# 使用渲染 prop 完成 Tabs

我们将通过使用渲染 prop 模式来完成我们的 Tabs 组件。在我们实现第一个渲染 prop 之前，让我们考虑一下当`Tabs`组件完成后，我们希望消费者如何消费它。以下的 JSX 是我们理想情况下从`Product`组件中消费`Tabs`组件的方式：

```jsx
<Tabs>
  <Tabs.Tab
    name="Description"
    initialActive={true}
    heading={() => <b>Description</b>}
  >
    <p>{product.description}</p>
  </Tabs.Tab>

  <Tabs.Tab 
    name="Reviews"
    heading={() => "Reviews"} 
  >
    <ul className="product-reviews">
      {product.reviews.map(review => (
        <li key={review.reviewer}>
          <i>"{review.comment}"</i> - {review.reviewer}
        </li>
      ))}
    </ul>
  </Tabs.Tab>
</Tabs>
```

让我们来看看这些关键部分的步骤：

+   我们仍然在使用复合组件。渲染 prop 与这些组件完全兼容。

+   每个选项卡的标题不再在`Tab`组件的子元素中定义。相反，我们使用一个`heading`渲染 prop，在那里我们仍然可以呈现简单的字符串或更丰富的内容。

+   然后指定选项卡内容为`Tab`组件的子元素。

# 使用渲染 prop 来设置选项卡标题

因此，让我们改变选项卡标题的实现，使用渲染 prop：

1.  在`Tabs.tsx`中，让我们首先在选项卡 props 接口中添加一个新的属性用于标题：

```jsx
interface ITabProps {
  name: string;
  initialActive?: boolean;
  heading: () => string | JSX.Element;
}
```

这个属性是一个没有参数的函数，返回一个`string`或一些 JSX。这就是我们的渲染 prop 的定义。

1.  更改实现非常简单。我们只需在`Tab`组件的返回语句中用新的渲染 prop 函数替换对`children`prop 函数的调用：

```jsx
return (
  <li
    onClick={handleTabClick}
    className={props.name === activeName ? "active" : ""}
  >
    {props.heading()}
  </li>
);
```

1.  让我们将`Product.tsx`中`Tabs`的使用切换为以下内容：

```jsx
<Tabs>
  <Tabs.Tab
    name="Description"
    initialActive={true}
    heading={() => <b>Description</b>}
  />
  <Tabs.Tab name="Reviews" heading={() => "Reviews"} />
</Tabs>
```

我们可能会收到一个 TSLint 警告：由于其渲染性能影响，JSX 属性中禁止使用 lambda。知道 lambda 可能会有问题是有用的，这样我们在遇到性能问题时可以记住这一点。然而，我们将在`tslint.json`中关闭此规则，指定`"jsx-no-lambda"`为`false`：

```jsx
{
  "extends": ["tslint:recommended", "tslint-react", "tslint-config-prettier"],
  "rules": {
    ...
    "jsx-no-lambda": false
  },
  ...
}
```

如果我们想要非常关注性能，我们可以引用组件内的方法，而不是使用 lambda 函数。

在保存了新的 TSLint 设置之后，编译器的投诉希望会消失。请注意，我们可能需要杀死终端并再次启动应用程序以消除编译器的投诉。

如果我们尝试在我们的应用程序中使用产品页面，它将表现得和以前一样。

因此，实现渲染属性模式非常简单。使用此模式最耗时的事情是理解它可以做什么以及它是如何工作的。一旦我们掌握了它，它就是一个可以为我们组件的消费者提供渲染灵活性的优秀模式。

在我们的`Tab`组件完成之前，我们还有最后一个部分要完成。

# 使用“children”属性来呈现选项卡内容。

现在我们的`Tab`组件已经接近完成了。最后的任务是允许消费者呈现选项卡内容。我们将使用`children`属性来实现这一点：

1.  首先，在`Tabs.tsx`中，让我们将上下文接口中的`handleTabClick`属性更改为包括要呈现的内容：

```jsx
interface ITabsContext {
  activeName: string;
  handleTabClick?: (name: string, content: React.ReactNode) => void;
}
```

1.  我们还将在状态接口中保存活动内容以及活动选项卡名称。因此，让我们将其添加到`Tabs`的状态接口中：

```jsx
interface IState {
  activeName: string;
  activeContent: React.ReactNode;
}
```

1.  现在让我们在`Tabs`中更改选项卡点击处理程序，以设置活动内容的状态以及活动选项卡名称：

```jsx
private handleTabClick = (name: string, content: React.ReactNode) => {
  this.setState({ activeName: name, activeContent: content });
};
```

1.  在`Tab`组件中，让我们通过传递`children`属性来调用选项卡点击处理程序，以获取选项卡内容的附加参数：

```jsx
const handleTabClick = (e: React.MouseEvent<HTMLLIElement>) => {
  if (context.handleTabClick) {
    context.handleTabClick(props.name, props.children);
  }
};
```

1.  现在让我们在`Tabs``render`方法中呈现我们状态中的活动内容，就在我们呈现选项卡标题的下面：

```jsx
<TabsContext.Provider ...
>
  <ul className="tabs">{this.props.children}</ul>
  <div>{this.state && this.state.activeContent}</div>
</TabsContext.Provider>
```

1.  让我们改变在`Product`组件中使用`Tabs`组件的方式：

```jsx
<h1>{product.name}</h1>

<Tabs>
 <Tabs.Tab
 name="Description"
 initialActive={true}
 heading={() => <b>Description</b>}
 >
 <p>{product.description}</p>
 </Tabs.Tab>

 <Tabs.Tab name="Reviews" heading={() => "Reviews"}>
 <ul className="product-reviews">
 {product.reviews.map(review => (
 <li key={review.reviewer}>
 <i>"{review.comment}"</i> - {review.reviewer}
 </li>
 ))}
 </ul>
 </Tabs.Tab>
</Tabs>

<p className="product-price">
...
</p>
```

现在选项卡内容已经嵌套在每个`Tab`组件中，正如我们所希望的那样。

让我们试一试。如果我们转到产品页面，我们会注意到一个问题：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/f8461702-bc71-4f68-9eb0-8e684520a27d.png)

在页面首次加载时未呈现内容。如果我们单击“Reviews”选项卡或“Description”选项卡，然后内容就会加载。

1.  问题在于当选项卡初始加载时，我们没有任何代码来呈现内容。因此，让我们通过在`Tab`组件中添加高亮显示的行来解决这个问题：

```jsx
public static Tab: React.SFC<ITabProps> = props => (
 <TabsContext.Consumer>
 {(context: ITabsContext) => {
  if (!context.activeName && props.initialActive) {
 if (context.handleTabClick) {
 context.handleTabClick(props.name, props.children);
 return null;
 }
 }
 const activeName = context.activeName
 ? context.activeName
 : props.initialActive
 ? props.name
 : "";
 ...
 }}
 </TabsContext.Consumer>
);
```

高亮显示的行在上下文中没有活动选项卡并且选项卡被标记为初始活动时，调用选项卡点击处理程序。在这种情况下，我们返回 null，因为调用选项卡点击将设置活动选项卡的状态，这将导致另一个渲染周期。

我们的选项卡组件现在应该已经完成了。让我们通过转到产品页面来检查：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/cc55df59-386e-410e-a76f-6f37c42b5e7f.png)

内容呈现如我们所期望的那样。 如果我们点击评论选项卡，这也会很好地呈现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5bae7243-ea0b-4a76-bcb1-7cb5e88cac12.png)

因此，渲染道具和子道具模式非常适合允许消费者渲染自定义内容。 语法一开始可能看起来有点棘手，但当你理解它时，它就变得非常合理和优雅。

在下一节中，我们将看一下本章中的最终模式。

# 高阶组件

**高阶组件**（**HOC**）是一个将组件作为参数并返回增强版本的函数组件。 这可能不太明晰，因此我们将在本节中通过一个示例来说明。 我们的示例创建了一个名为`withLoader`的 HOC，可以应用于任何组件，以在组件忙碌时添加加载旋转器。 我们将在我们的 React 商店（我们在上一节中工作过的）中使用它在产品页面上获取数据时。 完成后将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/9454161c-6159-4d83-8f20-a1bd53e4137a.png)

# 添加异步数据获取

目前，我们商店中的数据获取是瞬时的，因为所有数据都是本地的。 因此，在着手处理`withLoader`组件之前，让我们重构数据获取函数，包括延迟和异步。 这将更好地模拟使用 Web API 获取数据的真实数据获取函数：

1.  在`ProductData.ts`中，让我们添加以下箭头函数，用于获取产品：

```jsx
export const getProduct = async (id: number): Promise<IProduct | null> => {
  await wait(1000);
  const foundProducts = products.filter(customer => customer.id === id);
  return foundProducts.length === 0 ? null : foundProducts[0];
};
```

该函数接受产品 ID 并使用`products`数组中的`filter`函数找到产品，然后返回它。

该函数以`async`关键字为前缀，因为它是异步的。

1.  该函数还使用`await`关键字异步调用名为`wait`的函数。 因此，让我们创建`wait`函数：

```jsx
const wait = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};
```

该函数使用标准的 JavaScript `setTimeout`函数等待我们在函数参数中指定的毫秒数。 该函数返回一个在`setTimeout`完成时解析的`Promise`。

如果此刻`async`和`await`关键字以及承诺不太明晰，不要担心。 我们将在本书的后面详细讨论这些。

因此，我们现在有一个异步获取产品的函数，至少需要 1 秒。让我们将其插入到我们的产品页面中。`ProductPage`组件是一个负责获取数据的容器组件，所以让我们在这里插入它。

1.  首先，让我们将`getProduct`函数导入到`ProductPage`中：

```jsx
import { getProduct, IProduct } from "./ProductsData";
```

1.  让我们向`ProductPage`的状态添加一个名为`loading`的属性，以指示数据是否正在加载：

```jsx
interface IState {
  product?: IProduct;
  added: boolean;
  loading: boolean;
}
```

1.  让我们在构造函数中也将这个状态初始化为`true`：

```jsx
public constructor(props: Props) {
  super(props);
  this.state = {
    added: false,
    loading: true
  };
}
```

1.  现在，我们可以在`ProductPage`组件加载时使用`getProduct`函数：

```jsx
public async componentDidMount() {
  if (this.props.match.params.id) {
    const id: number = parseInt(this.props.match.params.id, 10);
    const product = await getProduct(id);
    if (product !== null) {
      this.setState({ product, loading: false });
    }
  }
}
```

我们使用`await`关键字异步调用`getProduct`。为了做到这一点，我们需要使用`async`关键字将`componentDidMount`生命周期方法标记为异步。在获取产品后，我们将其设置在状态中，并将`loading`标志重置为`false`。

1.  如果我们的商店没有运行，让我们运行这个：

```jsx
npm start
```

如果我们转到产品页面，我们会发现产品加载大约需要 1 秒。您可能会注意到在产品加载时显示“产品未找到！”。这是因为产品在初始渲染时未设置。我们暂时忽略这个问题，因为我们的`withLoader`HOC 将解决这个问题。

因此，现在我们正在异步获取数据，大约需要 1 秒，我们准备实现我们的`withLoader`HOC 并在产品页面上使用它。我们将在下一节中完成这个操作。

# 实现`withLoader` HOC

我们将创建一个名为`withLoader`的加载器组件，可以与任何组件一起使用，以指示组件正在忙于执行某些操作：

1.  让我们首先创建一个名为`withLoader.tsx`的新文件，内容如下：

```jsx
import * as React from "react";

interface IProps {
  loading: boolean;
}

const withLoader = <P extends object>(
  Component: React.ComponentType<P>
): React.SFC<P & IProps> => ({ loading, ...props }: IProps) =>
  // TODO - return a loading spinner if loading is true otherwise return the component passed in 

export default withLoader;
```

这里有一些事情正在发生，让我们来分解一下：

+   `withLoader`是一个接受类型为`P`的组件的函数。

+   `withLoader`调用一个函数组件。

+   函数组件的属性被定义为`P & IProps`，这是一个交集类型。

交集类型将多种类型合并为一个。因此，`X`，`Y`和`Z`将`X`，`Y`和`Z`的所有属性和方法合并到一个新类型中。

+   因此，SFC 的属性包括从传入的组件中获取的所有属性，以及我们定义的`loading`布尔属性。

+   使用剩余参数，将 props 解构为一个`loading`变量和一个包含所有其他属性的`props`变量。

1.  因此，我们剩下要做的工作是，如果`loading`为`true`，则返回我们的加载旋转器，否则我们只需要返回传入的组件。我们可以使用下面代码中窗口中突出显示的三元表达式来实现这一点：

```jsx
const withLoader = <P extends object>(
  Component: React.ComponentType<P>
): React.SFC<P & IProps> => ({ loading, ...props }: IProps) =>
  loading ? (
 <div className="loader-overlay">
 <div className="loader-circle-wrap">
 <div className="loader-circle" />
 </div>
 </div>
 ) : (
 <Component {...props} />
 );
```

传入的组件在第二个三元分支中返回。我们使用扩展语法将`props`变量中的属性扩展到组件中。

加载旋转器在第一个三元分支中返回。

1.  加载旋转器引用了一些 CSS 类，所以让我们把它们添加到`index.css`中：

```jsx
.loader-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: Black;
  opacity: 0.3;
  z-index: 10004;
}
.loader-circle-wrap {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  height: 100px;
  width: 100px;
  margin: auto;
}
.loader-circle {
  border: 4px solid #ffffff;
  border-top: 4px solid #899091;
  border-radius: 50%;
  width: 100px;
  height: 100px;
  animation: loader-circle-spin 0.7s linear infinite;
}
```

`loader-overlay`类在整个页面上创建一个黑色的透明覆盖层。`loader-circle-wrap`类在覆盖层的中心创建一个`100px`乘`100px`的正方形。`loader-circle`类创建旋转的圆圈。

我们的`withLoader` HOC 现在已经完成。

供参考，下面的代码块显示了基于类的`withLoader`版本：

```jsx
const withLoader = <P extends object>(Component: React.ComponentType<P>) =>
  class WithLoader extends React.Component<P & IProps> {
    public render() {
      const { loading, ...props } = this.props as IProps;
      return loading ? (
        <div className="loader-overlay">
          <div className="loader-circle-wrap">
            <div className="loader-circle" />
          </div>
        </div>
      ) : (
        <Component {...props} />
      );
    }
  };
```

我们将坚持使用 SFC 版本，因为它不包含任何状态，也不需要访问任何生命周期方法。

在下一节中，我们将在商店应用程序中的产品页面中使用我们的`withLoader`组件。

# 使用 withLoader HOC

使用 HOC 非常简单。我们只需将 HOC 包装在我们想增强的组件周围。这样做的最简单的地方是在导出语句中。

让我们将在上一节中创建的`withLoader` HOC 添加到我们的产品页面中：

1.  因此，我们将使用`withLoader`来包装`Product`组件。首先，让我们将`withLoader`导入到`Product.tsx`中：

```jsx
import withLoader from "./withLoader";
```

1.  现在我们可以在导出语句中将`withLoader`包装在`Product`周围：

```jsx
export default withLoader(Product);
```

现在，在`ProductPage`组件中，我们得到了一个编译错误，因为它期望向`Product`传递一个 loading 属性。

1.  因此，让我们在引用`Product`时，从加载状态中传递 loading 属性：

```jsx
<Product
  loading={this.state.loading}
  product={product}
  inBasket={this.state.added}
  onAddToBasket={this.handleAddClick}
/>
```

1.  在`ProductPage.tsx`中，我们应该修改渲染`Product`组件的条件。现在，如果产品仍在加载，我们希望渲染`Product`。然后将渲染加载旋转器：

```jsx
{product || this.state.loading ? (
  <Product
    loading={this.state.loading}
    product={product}
    inBasket={this.state.added}
    onAddToBasket={this.handleAddClick}
  />
) : (
  <p>Product not found!</p>
)}
```

然而，这会导致另一个编译错误，因为`Product`组件内的`product`属性不希望是`undefined`。然而，在加载产品时它将是`undefined`。

1.  因此，让我们在`IProps`中将这个属性设为可选的，用于`Product`组件：

```jsx
interface IProps {
  product?: IProduct;
  inBasket: boolean;
  onAddToBasket: () => void;
}
```

这样，在`Product`组件中引用`product`属性时，JSX 中会出现进一步的编译错误，因为在加载数据时它现在将是`undefined`。

1.  一个简单的解决方法是，如果我们没有产品，就渲染`null`。`withLoader`高阶组件在这种情况下会渲染一个加载旋转器。所以，我们只是让 TypeScript 编译器在这里很高兴：

```jsx
const handleAddClick = () => {
  props.onAddToBasket();
};
if (!product) {
 return null;
}
return (
  <React.Fragment>
    ...
  </React.Fragment>
);
```

现在 TypeScript 编译器很高兴，如果我们去商店的产品页面，它将在渲染产品之前显示我们的加载旋转器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/13a53776-e0bb-4729-8884-3a88283ab8f7.png)

因此，高阶组件非常适合增强组件，其中增强是可以应用于许多组件的东西。我们的加载旋转器是高阶组件的一个常见用例。另一个非常常见的 HOC 模式的用法是在使用 React Router 时。在本书的前面，我们使用了 React Router 的`withRouter`高阶组件来访问路径的参数。

# 总结

在本章中，我们学习了容器组件以及它们如何用于管理状态以及展示组件需要做什么。然后展示组件可以专注于它们需要看起来的样子。这使得展示组件可以更容易地在多个地方重复使用并进行单元测试。

我们学到了复合组件是相互依赖的组件。在父类上将复合子项声明为静态成员，可以清楚地告诉消费者这些组件应该一起使用。React 上下文是复合组件共享状态的便捷方式。

我们学到了特殊的 children 属性，可以用来访问和渲染组件的子项。然后我们学到，我们可以创建自己的渲染属性，为消费者提供对组件的自定义渲染部分的极大灵活性。

在上一节中，我们学习了高阶组件以及它们如何用于实现对组件的常见增强。在本书的前面，我们已经使用了 React Router 高阶组件来获取路径参数。

在下一章中，我们将学习如何在 React 中创建表单。在下一章的末尾，我们将使用本章学到的一些模式来以通用的方式处理表单。

# 问题

让我们用一些问题来测试一下我们对组件模式的学习成果：

1.  React 给我们提供了什么特殊属性来访问组件的子项？

1.  有多少组件可以通过 React 上下文共享状态？

1.  在使用 React 上下文时，它使用什么模式来允许我们使用上下文渲染我们的内容？

1.  一个组件中有多少个渲染 props？

1.  一个组件中有多少个 children props？

1.  我们只在产品页面上使用了`withLoader`。我们在`ProductData.ts`中使用以下函数来获取所有产品：

```jsx
export const getProducts = async (): Promise<IProduct[]> => {
  await wait(1000);
  return products;
};
```

你能用这个来通过使用`withLoader`高阶组件在产品页面上实现一个加载器吗？

1.  是否可以使用 children props 模式来创建一个加载器？消费的 JSX 可能如下所示：

```jsx
<Loader loading={this.state.loading}>
  <div>
    The content for my component ...
  </div>
</Loader>
```

如果可以的话，试着去实现它。

# 进一步阅读

+   React 上下文在 React 文档中有详细说明，链接如下：[`reactjs.org/docs/context.html`](https://reactjs.org/docs/context.html)

+   高阶组件在 React 文档中有详细说明，链接如下：[`reactjs.org/docs/higher-order-components.html`](https://reactjs.org/docs/higher-order-components.html)

+   渲染 props 模式在 React 文档中有详细说明，链接如下：[`reactjs.org/docs/render-props.html`](https://reactjs.org/docs/render-props.html)


# 第七章：处理表单

表单在我们构建的应用程序中非常常见。在本章中，我们将学习如何在 React 和 TypeScript 中使用受控组件构建表单。作为学习练习，我们将为我们在其他章节中一直在开发的 React 商店构建一个联系我们表单。

我们很快会发现，在创建表单时涉及大量样板代码，因此我们将研究构建通用表单组件以减少样板代码。客户端验证对我们构建的表单的用户体验至关重要，因此我们还将深入讨论这个主题。

最后，表单提交是一个关键考虑因素。我们将介绍如何处理提交错误，以及成功情况。

在本章中，我们将讨论以下主题：

+   使用受控组件创建表单

+   使用通用组件减少样板代码

+   验证表单

+   表单提交

# 技术要求

我们将在本章中使用以下技术：

+   **Node.js**和`npm`：TypeScript 和 React 依赖于这些。可以从以下链接安装它们：[`nodejs.org/en/download/`](https://nodejs.org/en/download)。如果您已经安装了这些，请确保`npm`至少是 5.2 版本。

+   **Visual Studio Code**：我们需要一个编辑器来编写 React 和 TypeScript

代码，可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)安装。我们还需要 TSLint 扩展（由 egamma 提供）和 Prettier 扩展（由 Estben Petersen 提供）。

+   **React 商店**：我们将从第六章完成的 React 商店项目开始，*组件模式*。这可以在 GitHub 上找到：[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/06-ComponentPatterns`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/06-ComponentPatterns)。

为了从上一章节恢复代码，可以在[`github.com/carlrip/LearnReact17WithTypeScript`](https://github.com/carlrip/LearnReact17WithTypeScript)上下载`LearnReact17WithTypeScript`存储库。然后可以在 Visual Studio Code 中打开相关文件夹，然后在终端中输入`npm install`来进行恢复。本章中的所有代码片段都可以在[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/07-WorkingWithForms`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/07-WorkingWithForms)上找到。

# 使用受控组件创建表单

表单是大多数应用程序的常见部分。在 React 中，创建表单的标准方式是使用所谓的*受控组件*。受控组件的值与 React 中的状态同步。当我们实现了我们的第一个受控组件时，这将更有意义。

我们将扩展我们一直在构建的 React 商店，以包括一个联系我们表单。这将使用受控组件来实现。

# 添加联系我们页面

在我们开始处理表单之前，我们需要一个页面来承载表单。该页面将是一个容器组件，我们的表单将是一个展示组件。我们还需要创建一个导航选项，可以带我们到我们的新页面。

在开始实现我们的表单之前，我们将写下以下代码：

1.  如果还没有，打开在 Visual Studio Code 中的 React 商店项目。在`src`文件夹中创建一个名为`ContactUsPage.tsx`的新文件，其中包含以下代码：

```jsx
import * as React from "react";

class ContactUsPage extends React.Component {
  public render() {
    return (
      <div className="page-container">
        <h1>Contact Us</h1>
        <p>
         If you enter your details we'll get back to you as soon as  
         we can.
        </p>
      </div>
    );
  }
}

export default ContactUsPage;
```

这个组件最终将包含状态，因此我们创建了一个基于类的组件。目前，它只是简单地呈现一个带有一些说明的标题。最终，它将引用我们的表单。

1.  现在让我们将这个页面添加到可用的路由中。打开`Routes.tsx`，并导入我们的页面：

```jsx
import ContactUsPage from "./ContactUsPage";
```

1.  在`Routes`组件的`render`方法中，我们现在可以在`admin`路由的上方添加一个新路由到我们的页面：

```jsx
<Switch>
  <Redirect exact={true} from="/" to="/products" />
  <Route path="/products/:id" component={ProductPage} />
  <Route exact={true} path="/products" component={ProductsPage} />
  <Route path="/contactus" component={ContactUsPage} />
  <Route path="/admin">
    ...
  </Route>
  <Route path="/login" component={LoginPage} />
  <Route component={NotFoundPage} />
</Switch>
```

1.  现在打开`Header.tsx`，其中包含所有的导航选项。让我们在管理员链接的上方添加一个`NavLink`到我们的新页面：

```jsx
<nav>
  <NavLink to="/products" className="header-link" activeClassName="header-link-active">
    Products
  </NavLink>
  <NavLink to="/contactus" className="header-link" activeClassName="header-link-active">
 Contact Us
 </NavLink>
  <NavLink to="/admin" className="header-link" activeClassName="header-link-active">
    Admin
  </NavLink>
</nav>
```

1.  通过在终端中输入以下内容，在开发服务器中运行项目：

```jsx
npm start
```

你应该看到一个新的导航选项，可以带我们到我们的新页面：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/a3962f6b-53ca-42b1-a6b3-d987b02f8944.png)

现在我们有了新页面，我们准备在表单中实现我们的第一个受控输入。我们将在下一节中完成这个任务。

# 创建受控输入

在这一部分，我们将开始创建包含我们第一个受控输入的表单：

1.  在`src`文件夹中创建一个名为`ContactUs.tsx`的新文件，其中包含以下代码：

```jsx
import * as React from "react";

const ContactUs: React.SFC = () => {
  return (
    <form className="form" noValidate={true}>
      <div className="form-group">
        <label htmlFor="name">Your name</label>
        <input type="text" id="name" />
      </div>
    </form>
  );
};

export default ContactUs;
```

这是一个函数组件，用于呈现一个包含用户姓名标签和输入框的表单。

1.  我们引用了一些 CSS 类，所以让我们把它们添加到`index.css`的底部：

```jsx
.form {
  width: 300px;
  margin: 0px auto 0px auto;
}

.form-group {
  display: flex;
  flex-direction: column;
  margin-bottom: 20px;
}

.form-group label {
  align-self: flex-start;
  font-size: 16px;
  margin-bottom: 3px;
}

.form-group input, select, textarea {
  font-family: Arial;
  font-size: 16px;
  padding: 5px;
  border: lightgray solid 1px;
  border-radius: 5px;
}
```

`form-group`类将包装表单中的每个字段，显示标签在输入框上方，并具有良好的间距。

1.  现在让我们从我们的页面引用我们的表单。转到`ContactUsPage.tsx`并导入我们的组件：

```jsx
import ContactUs from "./ContactUs";
```

1.  然后我们可以在`div`容器底部的`render`方法中引用我们的组件：

```jsx
<div className="page-container">
  <h1>Contact Us</h1>
  <p>If you enter your details we'll get back to you as soon as we can.</p>
  <ContactUs />
</div>
```

如果我们查看正在运行的应用程序并转到联系我们页面，我们将看到我们的名字字段被呈现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/dc455066-7714-4043-916e-3cd46c5e0eb0.png)

我们可以将我们的名字输入到这个字段中，但目前什么也不会发生。我们希望输入的名字存储在`ContactUsPage`容器组件的状态中。这是因为`ContactUsPage`最终将管理表单提交。

1.  让我们为`ContactUsPage`添加一个状态类型：

```jsx
interface IState {
 name: string;
 email: string;
 reason: string;
 notes: string;
}

class ContactUsPage extends React.Component<{}, IState> { ... }
```

除了人的名字，我们还将捕获他们的电子邮件地址，联系商店的原因以及任何其他附加说明。

1.  让我们还在构造函数中初始化状态：

```jsx
public constructor(props: {}) {
  super(props);
  this.state = {
    email: "",
    name: "",
    notes: "",
    reason: ""
  };
}
```

1.  现在，我们需要将`ContactUsPage`中的名字值传递到`ContactUs`组件中。这将允许我们在输入框中显示该值。我们可以通过首先在`ContactUs`组件中创建 props 来实现这一点：

```jsx
interface IProps {
 name: string;
 email: string;
 reason: string;
 notes: string;
}

const ContactUs: React.SFC<IProps> = props => { ... }
```

我们已为我们最终要捕获的所有数据创建了 props。

1.  现在，我们可以将名字输入值绑定到`name`属性：

```jsx
<div className="form-group">
  <label htmlFor="name">Your name</label>
  <input type="text" id="name" value={props.name} />
</div>
```

1.  现在，我们可以从`ContactUsPage`的状态中传递这些：

```jsx
<ContactUs 
  name={this.state.name} 
 email={this.state.email} 
 reason={this.state.reason} 
 notes={this.state.notes} 
/>
```

让我们去运行的应用程序并转到我们的联系我们页面。尝试在名字输入框中输入一些内容。

似乎什么都没有发生……有什么东西阻止我们输入值。

我们刚刚将输入值设置为一些 React 状态，因此 React 现在控制着输入的值。这就是为什么我们似乎不再能够输入的原因。

我们正在创建我们的第一个受控输入。但是，如果用户无法输入任何内容，受控输入就没有多大用处。那么，我们如何使输入框再次可编辑呢？

答案是我们需要监听输入值的更改，并相应地更新状态。然后 React 将从状态中呈现新的输入值。

1.  让我们通过`onChange`属性监听输入的更改：

```jsx
<input type="text" id="name" value={props.name} onChange={handleNameChange} />
```

1.  让我们也创建我们刚刚引用的处理程序：

```jsx
const ContactUs: React.SFC<IProps> = props => {
  const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
 props.onNameChange(e.currentTarget.value);
 };
  return ( ... );
};
```

请注意，我们已经使用了通用的`React.ChangeEvent`命令，其类型为我们正在处理的元素（`HTMLInputElement`）。

事件参数中的`currentTarget`属性为我们提供了事件处理程序所附加到的元素的引用。其中的`value`属性为我们提供了输入的最新值。

1.  处理程序引用了一个我们尚未定义的`onNameChange`函数属性。因此，让我们将其添加到我们的接口中，以及其他字段的类似属性：

```jsx
interface IProps {
  name: string;
  onNameChange: (name: string) => void;
  email: string;
  onEmailChange: (email: string) => void;
  reason: string;
  onReasonChange: (reason: string) => void;
  notes: string;
  onNotesChange: (notes: string) => void;
}
```

1.  现在我们可以将这些 props 从`ContactUsPage`传递到`ContactUs`：

```jsx
<ContactUs
  name={this.state.name}
  onNameChange={this.handleNameChange}
  email={this.state.email}
  onEmailChange={this.handleEmailChange}
  reason={this.state.reason}
  onReasonChange={this.handleReasonChange}
  notes={this.state.notes}
  onNotesChange={this.handleNotesChange}
/>
```

1.  让我们在`ContactUsPage`中创建我们刚刚引用的更改处理程序，设置相关状态：

```jsx
private handleNameChange = (name: string) => {
  this.setState({ name });
};
private handleEmailChange = (email: string) => {
  this.setState({ email });
};
private handleReasonChange = (reason: string) => {
  this.setState({ reason });
};
private handleNotesChange = (notes: string) => {
  this.setState({ notes });
};
```

如果我们现在去运行应用程序中的联系我们页面，并输入一些内容到姓名中，这次输入会按预期的方式行为。

1.  让我们在`ContactUs`的`render`方法中添加电子邮件、原因和备注字段：

```jsx
<form className="form" noValidate={true} onSubmit={handleSubmit}>
  <div className="form-group">
    <label htmlFor="name">Your name</label>
    <input type="text" id="name" value={props.name} onChange={handleNameChange} />
  </div>

  <div className="form-group">
 <label htmlFor="email">Your email address</label>
 <input type="email" id="email" value={props.email} onChange={handleEmailChange} />
 </div>

 <div className="form-group">
 <label htmlFor="reason">Reason you need to contact us</label>
 <select id="reason" value={props.reason} onChange={handleReasonChange}>
 <option value="Marketing">Marketing</option>
 <option value="Support">Support</option>
 <option value="Feedback">Feedback</option>
 <option value="Jobs">Jobs</option>
 <option value="Other">Other</option>
 </select>
 </div>

 <div className="form-group">
 <label htmlFor="notes">Additional notes</label>
 <textarea id="notes" value={props.notes} onChange={handleNotesChange} />
 </div>
</form>
```

对于每个字段，我们在`div`容器中呈现一个`label`和适当的编辑器，使用`form-group`类来很好地间隔我们的字段。

所有编辑器都引用处理更改值的处理程序。所有编辑器还从适当的`ContactUs`属性中设置其值。因此，所有字段编辑器都是受控组件。

让我们更仔细地看一下`select`编辑器。我们使用`value`属性在`select`标签中设置值。然而，这在原生的`select`标签中并不存在。通常情况下，我们必须在`select`标签中的相关`option`标签中包含一个`selected`属性：

```jsx
<select id="reason">
  <option value="Marketing">Marketing</option>
  <option value="Support" **selected**>Support</option>
  <option value="Feedback">Feedback</option>
  <option value="Jobs">Jobs</option>
  <option value="Other">Other</option>
</select>
```

React 在`select`标签中添加了`value`属性，并在幕后管理`option`标签上的`selected`属性。这使我们能够一致地在我们的代码中管理`input`、`textarea`和`selected`。

1.  现在让我们为这些字段创建更改处理程序，调用我们之前创建的函数 props：

```jsx
const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  props.onEmailChange(e.currentTarget.value);
};
const handleReasonChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
  props.onReasonChange(e.currentTarget.value);
};
const handleNotesChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
  props.onNotesChange(e.currentTarget.value);
};
```

这完成了我们基本的联系我们表单，使用各种受控表单元素。我们还没有实现任何验证或提交表单。我们将在本章后面处理这些问题。

我们已经注意到为每个字段获取字段更改到状态的类似代码。在下一节中，我们将开始开发一个通用表单组件，并切换到使用它来处理我们的联系我们表单。

# 使用通用组件减少样板代码

通用表单组件将有助于减少实现表单所需的代码量。在本节中，我们将对我们在上一节中为`ContactUs`组件所做的事情进行重构。

让我们考虑如何理想地使用通用组件来生成`ContactUs`组件的新版本。它可能是以下 JSX 的样子：

```jsx
<Form
  defaultValues={{ name: "", email: "", reason: "Support", notes: "" }}
>
  <Form.Field name="name" label="Your name" />
  <Form.Field name="email" label="Your email address" type="Email" />
  <Form.Field name="reason" label="Reason you need to contact us" type="Select" options={["Marketing", "Support", "Feedback", "Jobs", "Other"]} />
  <Form.Field name="notes" label="Additional notes" type="TextArea" />
</Form>
```

在这个例子中，有两个通用的复合组件：`Form`和`Field`。以下是一些关键点：

+   `Form`组件是复合组件的容器，管理状态和交互。

+   我们在`Form`组件的`defaultValues`属性中传递字段的默认值。

+   `Field`组件为每个字段渲染标签和编辑器。

+   每个字段都有一个`name`属性，它将确定状态中存储字段值的属性名称。

+   每个字段都有一个`label`属性，用于指定每个字段标签中显示的文本。

+   使用`type`属性指定特定的字段编辑器。默认编辑器是基于文本的`input`。

+   如果编辑器类型是`Select`，那么我们可以使用`options`属性指定出现在其中的选项。

渲染新的`ContactUs`组件的 JSX 比原始版本要短得多，而且可能更容易阅读。状态管理和事件处理程序被隐藏在`Form`组件中并封装起来。

# 创建一个基本的表单组件

是时候开始处理我们的通用`Form`组件了：

1.  让我们首先在`src`文件夹中创建一个名为`Form.tsx`的新文件，其中包含以下内容：

```jsx
import * as React from "react";

interface IFormProps {}

interface IState {}

export class Form extends React.Component<IFormProps, IState> {
  constructor(props: IFormProps) {}
  public render() {}
}
```

`Form`是一个基于类的组件，因为它需要管理状态。我们将 props 接口命名为`IFormProps`，因为以后我们将需要一个字段 props 的接口。

1.  让我们在`IFormProps`接口中添加一个`defaultValues`属性。这将保存表单中每个字段的默认值：

```jsx
export interface IValues {
 [key: string]: any;
}

interface IFormProps {
  defaultValues: IValues;
}
```

我们使用了一个名为`IValues`的额外接口来表示默认值类型。这是一个可索引的键/值类型，具有`string`类型的键和`any`类型的值。键将是字段名称，值将是字段值。

因此，`defaultValues`属性的值可以是这样的：

```jsx
{ name: "", email: "", reason: "Support", notes: "" }
```

1.  现在让我们继续处理`Form`中的状态。我们将在状态属性`values`中存储字段值：

```jsx
interface IState {
  values: IValues;
}
```

请注意，这与`defaultValues`属性的类型相同，即`IValues`。

1.  现在我们将在构造函数中使用默认值初始化状态：

```jsx
constructor(props: IFormProps) {
  super(props);
  this.state = {
    values: props.defaultValues
  };
}
```

1.  在本节中，我们要做的最后一件事是开始实现`Form`组件中的`render`方法：

```jsx
public render() {
 return (
 <form className="form" noValidate={true}>
 {this.props.children}
 </form>
 );
}
```

我们在`form`标签中渲染子组件，使用了我们在上一章中使用的神奇的`children`属性。

这很好地引出了`Field`组件，我们将在下一节中实现它。

# 添加一个基本的 Field 组件

`Field`组件需要渲染标签和编辑器。它将位于`Form`组件内部的静态属性`Field`中。消费者可以使用`Form.Field`来引用此组件：

1.  让我们首先在`Form.tsx`中为字段 props 创建一个接口，就在`IFormProps`上面：

```jsx
interface IFieldProps {
  name: string;
  label: string;
  type?: "Text" | "Email" | "Select" | "TextArea";
  options?: string[];
}
```

+   `name`属性是字段的名称。

+   `label`属性是要在字段标签中显示的文本。

+   `type`属性是要显示的编辑器类型。我们已经为此属性使用了联合类型，包含了我们将要支持的可用类型。请注意，我们已将其定义为可选属性，因此稍后需要为此定义一个默认值。

+   `options`属性仅适用于`Select`编辑器类型，也是可选的。这定义了要在下拉列表中显示的选项列表，是一个`string`数组。

1.  现在，让我们在`Form`中为`Field`组件添加一个骨架静态`Field`属性：

```jsx
public static Field: React.SFC<IFieldProps> = props => {
  return ();
};
```

1.  在我们忘记之前，让我们为字段`type`属性添加默认值。我们将其定义如下，在`Form`类的外部和下方：

```jsx
Form.Field.defaultProps = {
  type: "Text"
};
```

因此，默认的`type`将是基于文本的输入。

1.  现在，让我们尝试渲染字段：

```jsx
public static Field: React.SFC<IFieldProps> = props => {
  const { name, label, type, options } = props;
  return (
    <div className="form-group">
 <label htmlFor={name}>{label}</label>
 <input type={type.toLowerCase()} id={name} />
 </div>
  );
}
```

+   我们首先从 props 对象中解构`name`、`label`、`type`和`options`。

+   该字段被包裹在一个`div`容器中，使用`form-group`类在`index.css`中已经实现的方式在垂直方向上间隔字段。

+   然后，在`div`容器内部渲染`label`，`label`的`htmlFor`属性引用`input`的`id`。

这是一个很好的开始，但并非所有不同的字段编辑器都是输入。实际上，这只适用于`Text`和`Email`类型。

1.  因此，让我们稍微调整一下，并在输入周围包裹一个条件表达式：

```jsx
<label htmlFor={name}>{label}</label>
{(type === "Text" || type === "Email") && (
  <input type={type.toLowerCase()} id={name} />
)}
```

1.  接下来，让我们通过添加高亮的 JSX 来处理`TextArea`类型：

```jsx
{(type === "Text" || type === "Email") ... }

{type === "TextArea" && (
 <textarea id={name} />
)}
```

1.  现在，我们可以渲染我们将要支持的最终编辑器，如下所示：

```jsx
{type === "TextArea" ... } {type === "Select" && (
  <select>
    {options &&
      options.map(option => (
        <option key={option} value={option}>
          {option}
        </option>
      ))}
  </select>
)} 
```

我们渲染一个`select`标签，其中包含使用`options`数组属性中的`map`函数指定的选项。请注意，我们为每个选项分配一个唯一的`key`属性，以便在检测到选项的任何更改时保持 React 的正常运行。

现在，我们已经有了基本的`Form`和`Field`组件，这很棒。但是，实现仍然相当无用，因为我们尚未在状态中管理字段值。让我们在下一节中解决这个问题。

# 与 React 上下文共享状态

字段值的状态存储在`Form`组件中。但是，这些值是通过`Field`组件渲染和更改的。`Field`组件无法访问`Form`中的状态，因为状态存在于`Form`实例中，而`Field`没有。

这与我们在上一章中实现的复合`Tabs`组件非常相似。我们使用 React 上下文在`Tabs`复合组件之间共享状态。

在本节中，我们将使用相同的方法来处理`Forms`组件。

1.  让我们首先在`Form.tsx`中为表单上下文创建一个接口：

```jsx
interface IFormContext {
  values: IValues;
}
```

上下文只包含与我们状态中的`IValues`相同类型的值。

1.  现在让我们在`IFormContext`下方使用`React.createContext`创建上下文组件：

```jsx
const FormContext = React.createContext<IFormContext>({
  values: {}
});
```

通过将初始上下文值设置为空文字值，我们使 TypeScript 编译器满意。

1.  在`Form`的`render`方法中，创建包含状态中的值的上下文值：

```jsx
public render() {
  const context: IFormContext = {
 values: this.state.values
 };
  return ( ... )
}
```

1.  在`render`方法的 JSX 中的`form`标签周围包装上下文提供程序：

```jsx
<FormContext.Provider value={context}>
  <form ... >
    ...
  </form>
</FormContext.Provider>
```

1.  现在我们可以在`Field` SFC 中使用上下文：

```jsx
<FormContext.Consumer>
 {context => (
    <div className="form-group">
    </div>
 )}
</FormContext.Consumer>
```

1.  既然我们可以访问上下文了，让我们在所有三个编辑器中从中呈现值：

```jsx
<div className="form-group">
  <label htmlFor={name}>{label}</label>
  {(type === "Text" || type === "Email") && (
    <input type={type.toLowerCase()} id={name} value={context.values[name]} />
  )}

  {type === "TextArea" && (
    <textarea id={name} value={context.values[name]} />
  )}

  {type === "Select" && (
    <select value={context.values[name]}>
    ...
    </select>
  )}
</div>
```

TypeScript 编译器现在对我们的`Form`和`Field`组件满意了。因此，我们可以开始对新的`ContactUs`实现进行工作。

然而，用户现在还不能输入任何内容到我们的表单中，因为我们还没有处理更改并将新值传递给状态。现在我们需要实现更改处理程序。

1.  让我们首先在`Form`类中创建一个`setValue`方法：

```jsx
private setValue = (fieldName: string, value: any) => {
  const newValues = { ...this.state.values, [fieldName]: value };
  this.setState({ values: newValues });
};
```

这个方法的关键点如下：

+   该方法接受字段名称和新值作为参数。

+   使用一个名为`newValues`的新对象创建`values`对象的新状态，该对象展开了状态中的旧值，然后添加了新的字段名称和值。

+   然后在状态中设置新值。

1.  然后我们在表单上下文中创建对该方法的引用，以便`Field`组件可以访问它。让我们首先将其添加到表单上下文接口中：

```jsx
interface IFormContext {
  values: IValues;
  setValue?: (fieldName: string, value: any) => void;
}
```

我们将属性设置为可选，以便在创建表单上下文组件时使 TypeScript 编译器满意。

1.  然后我们可以在创建上下文值时在`Form`中创建对`setValue`方法的引用：

```jsx
const context: IFormContext = {
  setValue: this.setValue,
  values: this.state.values
};
```

1.  现在我们可以从`Field`组件中访问并调用这个方法。在`Field`中，在我们解构`props`对象之后，让我们创建一个更改处理程序来调用`setValue`方法：

```jsx
const { name, label, type, options } = props;

const handleChange = (
 e:
 | React.ChangeEvent<HTMLInputElement>
 | React.ChangeEvent<HTMLTextAreaElement>
 | React.ChangeEvent<HTMLSelectElement>,
 context: IFormContext
) => {
 if (context.setValue) {
 context.setValue(props.name, e.currentTarget.value);
 }
};
```

让我们来看看这个方法的关键点：

+   TypeScript 更改事件类型为`ChangeEvent<T>`，其中`T`是正在处理的元素的类型。

+   处理程序的第一个参数`e`是 React 的 change 事件处理程序参数。我们将所有不同的编辑器的 change 处理程序类型联合起来，这样我们就可以在一个函数中处理所有的变化。

+   处理程序的第二个参数是表单上下文。

+   我们需要一个条件语句来检查`setValue`方法是否不是`undefined`，以使 TypeScript 编译器满意。

+   然后我们可以使用字段名称和新值调用`setValue`方法。

1.  然后我们可以在`input`标签中引用这个 change handler，如下所示：

```jsx
<input 
  type={type.toLowerCase()} 
  id={name} 
  value={context.values[name]}
  onChange={e => handleChange(e, context)} 
/>
```

请注意，我们使用了一个 lambda 函数，这样我们就可以将上下文值传递给`handleChange`。

1.  我们也可以在`textarea`标签中这样做：

```jsx
<textarea 
  id={name} 
  value={context.values[name]} 
  onChange={e => handleChange(e, context)} 
/>
```

1.  我们也可以在`select`标签中这样做：

```jsx
<select 
 value={context.values[name]}
 onChange={e => handleChange(e, context)} 
>
 ...
</select>
```

因此，我们的`Form`和`Field`组件现在很好地协同工作，渲染字段并管理它们的值。在下一节中，我们将通过实现一个新的`ContactUs`组件来尝试我们的通用组件。

# 实现我们的新 ContactUs 组件

在本节中，我们将使用我们的`Form`和`Field`组件实现一个新的`ContactUs`组件：

1.  让我们首先从`ContactUs.tsx`中删除 props 接口。

1.  `ContactUs` SFC 中的内容将与原始版本非常不同。让我们首先删除内容，使其看起来如下：

```jsx
const ContactUs: React.SFC = () => {
  return ();
};
```

1.  让我们将我们的`Form`组件导入到`ContactUs.tsx`中：

```jsx
import { Form } from "./Form";
```

1.  现在我们可以引用`Form`组件，传递一些默认值：

```jsx
return (
  <Form
 defaultValues={{ name: "", email: "", reason: "Support", notes: "" }}
 >
 </Form>
);
```

1.  让我们添加`name`字段：

```jsx
<Form
  defaultValues={{ name: "", email: "", reason: "Support", notes: "" }}
>
  <Form.Field name="name" label="Your name" />
</Form>
```

请注意，我们没有传递`type`属性，因为这将默认为基于文本的输入，这正是我们需要的。

1.  现在让我们添加`email`，`reason`和`notes`字段：

```jsx
<Form
  defaultValues={{ name: "", email: "", reason: "Support", notes: "" }}
>
  <Form.Field name="name" label="Your name" />
  <Form.Field name="email" label="Your email address" type="Email" />
 <Form.Field
 name="reason"
 label="Reason you need to contact us"
 type="Select"
 options={["Marketing", "Support", "Feedback", "Jobs", "Other"]}
 />
 <Form.Field name="notes" label="Additional notes" type="TextArea" />
</Form>
```

1.  `ContactUsPage`现在会简单得多。它不会包含任何状态，因为现在状态是在`Form`组件中管理的。我们也不需要向`ContactUs`组件传递任何 props：

```jsx
class ContactUsPage extends React.Component<{}, {}> {
  public render() {
    return (
      <div className="page-container">
        <h1>Contact Us</h1>
        <p>
          If you enter your details we'll get back to you as soon as we can.
        </p>
        <ContactUs />
      </div>
    );
  }
}
```

如果我们转到运行中的应用程序并转到联系我们页面，它会按照要求呈现并接受我们输入的值。

我们的通用表单组件正在良好地进展，并且我们已经使用它来实现了`ContactUs`组件，正如我们所希望的那样。在下一节中，我们将通过添加验证进一步改进我们的通用组件。

# 验证表单

在表单中包含验证可以提高用户体验，让他们立即得到关于输入信息是否有效的反馈。在本节中，我们将为我们的`Form`组件添加验证，然后在我们的`ContactUs`组件中使用它。

我们将在`ContactUs`组件中实现的验证规则是这些：

+   名称和电子邮件字段应填写

+   名称字段应至少为两个字符

当字段编辑器失去焦点时，我们将执行验证规则。

在下一节中，我们将向`Form`组件添加一个属性，允许消费者指定验证规则。

# 向表单添加验证规则属性

让我们考虑如何指定验证规则给表单。我们需要能够为一个字段指定一个或多个规则。一些规则可能有参数，比如最小长度。如果我们能够像下面的示例那样指定规则就好了：

```jsx
<Form
  ...
  validationRules={{
 email: { validator: required },
 name: [{ validator: required }, { validator: minLength, arg: 3 }]
 }}
>
  ...
</Form>
```

让我们尝试在`Form`组件上实现`validationRules`属性：

1.  首先在`Form.tsx`中为`Validator`函数定义一个类型：

```jsx
export type Validator = (
  fieldName: string,
  values: IValues,
  args?: any
) => string;
```

`Validator`函数将接受字段名称、整个表单的值和特定于函数的可选参数。将返回包含验证错误消息的字符串。如果字段有效，则返回空字符串。

1.  让我们使用此类型创建一个`Validator`函数，以检查`Validator`类型下名为`required`的字段是否已填写：

```jsx
export const required: Validator = (
  fieldName: string,
  values: IValues,
  args?: any
): string =>
  values[fieldName] === undefined ||
  values[fieldName] === null ||
  values[fieldName] === ""
    ? "This must be populated"
    : "";
```

我们导出该函数，以便稍后在我们的`ContactUs`实现中使用。该函数检查字段值是否为`undefined`、`null`或空字符串，如果是，则返回必须填写此字段的验证错误消息。

如果字段值不是`undefined`、`null`或空字符串，则返回空字符串以指示该值有效。

1.  同样，让我们为检查字段输入是否超过最小长度创建一个`Validator`函数：

```jsx
export const minLength: Validator = (
  fieldName: string,
  values: IValues,
  length: number
): string =>
  values[fieldName] && values[fieldName].length < length
    ? `This must be at least ${length} characters`
    : "";
```

该函数检查字段值的长度是否小于长度参数，如果是，则返回验证错误消息。否则，返回空字符串以指示该值有效。

1.  现在，让我们通过一个属性向`Form`组件传递验证规则的能力：

```jsx
interface IValidation {
 validator: Validator;
 arg?: any;
}

interface IValidationProp {
 [key: string]: IValidation | IValidation[];
}

interface IFormProps {
  defaultValues: IValues;
  validationRules: IValidationProp;
}
```

+   `validationRules`属性是一个可索引的键/值类型，其中键是字段名称，值是一个或多个`IValidation`类型的验证规则。

+   验证规则包含`Validator`类型的验证函数和传递到验证函数的参数。

1.  有了新的`validationRules`属性，让我们将其添加到`ContactUs`组件中。首先导入验证函数：

```jsx
import { Form, minLength, required } from "./Form";
```

1.  现在，让我们将验证规则添加到`ContactUs`组件的 JSX 中：

```jsx
<Form
  defaultValues={{ name: "", email: "", reason: "Support", notes: "" }}
  validationRules={{
 email: { validator: required },
 name: [{ validator: required }, { validator: minLength, arg: 2 }]
 }}
>
  ...
</Form>
```

现在，如果名称和电子邮件已填写，并且名称至少为两个字符长，我们的表单就是有效的。

这就是`validationRules`prop 的完成。在下一节中，我们将跟踪验证错误消息，以准备在页面上呈现它们。

# 跟踪验证错误消息

当用户完成表单并字段变为有效或无效时，我们需要在状态中跟踪验证错误消息。稍后，我们将能够将错误消息呈现到屏幕上。

`Form`组件负责管理所有表单状态，因此我们将错误消息状态添加到其中，如下所示：

1.  让我们将验证错误消息状态添加到表单状态接口中：

```jsx
interface IErrors {
 [key: string]: string[];
}

interface IState {
  values: IValues;
  errors: IErrors;
}
```

`errors`状态是可索引的键/值类型，其中键是字段名称，值是验证错误消息的数组。

1.  让我们在构造函数中初始化`errors`状态：

```jsx
constructor(props: IFormProps) {
  super(props);
  const errors: IErrors = {};
 Object.keys(props.defaultValues).forEach(fieldName => {
 errors[fieldName] = [];
 });
  this.state = {
    errors,
    values: props.defaultValues
  };
}
```

`defaultValues`prop 包含其键中的所有字段名称。我们遍历`defaultValues`键，将适当的`errors`键设置为空数组。因此，当`Form`组件初始化时，没有任何字段包含任何验证错误消息，这正是我们想要的。

1.  `Field`组件最终将呈现验证错误消息，因此我们需要将这些添加到表单上下文中。让我们从将这些添加到表单上下文接口开始：

```jsx
interface IFormContext {
 errors: IErrors;  values: IValues;
  setValue?: (fieldName: string, value: any) => void;
}
```

1.  让我们在创建上下文时将`errors`空文字作为默认值添加。这是为了让 TypeScript 编译器满意：

```jsx
const FormContext = React.createContext<IFormContext>({
  errors: {},
  values: {}
});
```

1.  现在，我们可以在上下文值中包含错误：

```jsx
public render() {
  const context: IFormContext = {
    errors: this.state.errors,
    setValue: this.setValue,
    values: this.state.values
  };
  return (
    ...
  );
}
```

现在，验证错误在表单状态中，也在表单上下文中，以便`Field`组件可以访问。在下一节中，我们将创建一个方法来调用验证规则。

# 调用验证规则

到目前为止，我们可以定义验证规则，并且有状态来跟踪验证错误消息，但是还没有调用规则。这就是我们将在本节中实现的内容：

1.  我们需要在`Form`组件中创建一个方法，该方法将验证字段，调用指定的验证器函数。让我们创建一个名为`validate`的方法，该方法接受字段名称和其值。该方法将返回一个验证错误消息数组：

```jsx
private validate = (
  fieldName: string,
  value: any
): string[] => {

};
```

1.  让我们获取字段的验证规则并初始化一个`errors`数组。当验证器被执行时，我们将在`errors`数组中收集所有的错误。在所有验证器被执行后，我们还将返回`errors`数组：

```jsx
private validate = ( 
  fieldName: string,
  value: any
): string[] => {
  const rules = this.props.validationRules[fieldName];
 const errors: string[] = [];

  // TODO - execute all the validators

  return errors;
}
```

1.  规则可以是一个`IValidation`数组，也可以是一个单独的`IValidation`。让我们检查一下，如果只有一个验证规则，就调用`validator`函数：

```jsx
const errors: string[] = [];
if (Array.isArray(rules)) {
 // TODO - execute all the validators in the array of rules
} else {
  if (rules) {
    const error = rules.validator(fieldName, this.state.values, rules.arg);
    if (error) {
      errors.push(error);
    }
  }
}
return errors;
```

1.  现在让我们处理有多个验证规则时的代码分支。我们可以在规则数组上使用`forEach`函数来遍历规则并执行`validator`函数：

```jsx
if (Array.isArray(rules)) {
  rules.forEach(rule => {
 const error = rule.validator(
 fieldName,
 this.state.values,
 rule.arg
 );
 if (error) {
 errors.push(error);
 }
 });
} else {
  ...
}
return errors;
```

1.  我们需要在`validate`方法中实现的最后一部分代码是设置新的`errors`表单状态：

```jsx
if (Array.isArray(rules)) {
 ...
} else {
 ...
}
const newErrors = { ...this.state.errors, [fieldName]: errors };
this.setState({ errors: newErrors });
return errors;
```

我们将旧的错误状态扩展到一个新对象中，然后为字段添加新的错误。

1.  `Field`组件需要调用这个`validate`方法。我们将在表单上下文中添加对这个方法的引用。让我们先将它添加到`IFormContext`接口中：

```jsx
interface IFormContext {
  values: IValues;
  errors: IErrors;
  setValue?: (fieldName: string, value: any) => void;
  validate?: (fieldName: string, value: any) => void;
}
```

1.  现在我们可以在`Form`的`render`方法中将其添加到上下文值中：

```jsx
public render() {
  const context: IFormContext = {
    errors: this.state.errors,
    setValue: this.setValue,
    validate: this.validate,
    values: this.state.values
  };
  return (
    ...
  );
}
```

我们的表单验证进展顺利，现在我们有一个可以调用的方法来调用字段的所有规则。然而，这个方法还没有被从任何地方调用，因为用户填写表单。我们将在下一节中做这件事。

# 从字段触发验证规则执行

当用户填写表单时，我们希望在字段失去焦点时触发验证规则。我们将在本节中实现这一点：

1.  让我们创建一个函数，来处理三种不同编辑器的`blur`事件：

```jsx
const handleChange = (
  ...
};

const handleBlur = (
 e:
 | React.FocusEvent<HTMLInputElement>
 | React.FocusEvent<HTMLTextAreaElement>
 | React.FocusEvent<HTMLSelectElement>,
 context: IFormContext
) => {
 if (context.validate) {
 context.validate(props.name, e.currentTarget.value);
 }
};

return ( ... )
```

+   TypeScript 的模糊事件类型是`FocusEvent<T>`，其中`T`是正在处理的元素的类型。

+   处理程序的第一个参数`e`是 React 模糊事件处理程序参数。我们将所有不同的处理程序类型联合起来，这样我们就可以在一个函数中处理所有的模糊事件。

+   处理程序的第二个参数是表单上下文。

+   我们需要一个条件语句来检查`validate`方法是否不是`undefined`，以使 TypeScript 编译器满意。

+   然后我们可以使用字段名称和需要验证的新值调用`validate`方法。

1.  现在我们可以在文本和电子邮件编辑器的`Field` JSX 中引用这个处理程序：

```jsx
{(type === "Text" || type === "Email") && (
  <input
    type={type.toLowerCase()}
    id={name}
    value={context.values[name]}
    onChange={e => handleChange(e, context)}
    onBlur={e => handleBlur(e, context)}
  />
)}
```

我们将`onBlur`属性设置为调用我们的`handleBlur`函数的 lambda 表达式，同时传入模糊参数和上下文值。

1.  现在让我们在另外两个编辑器中引用这个处理程序：

```jsx
{type === "TextArea" && (
  <textarea
    id={name}
    value={context.values[name]}
    onChange={e => handleChange(e, context)}
    onBlur={e => handleBlur(e, context)}
  />
)}
{type === "Select" && (
  <select
    value={context.values[name]}
    onChange={e => handleChange(e, context)}
    onBlur={e => handleBlur(e, context)}
  >
    ...
  </select>
)}
```

我们的字段现在在失去焦点时执行验证规则。在我们尝试给我们的联系我们页面一个尝试之前，还有一项任务要做，我们将在下一节中完成。

# 渲染验证错误消息

在这一节中，我们将在`Field`组件中渲染验证错误消息：

1.  让我们在`form-group`的`div`容器底部显示所有错误，使用我们已经实现的`form-error` CSS 类的`span`：

```jsx
<div className="form-group">
  <label htmlFor={name}>{label}</label>
  {(type === "Text" || type === "Email") && (
    ...
  )}
  {type === "TextArea" && (
    ...
  )}
  {type === "Select" && (
    ...
  )}
  {context.errors[name] &&
 context.errors[name].length > 0 &&
 context.errors[name].map(error => (
 <span key={error} className="form-error">
 {error}
 </span>
 ))}
</div>
```

因此，我们首先检查字段名称是否有错误，然后在`errors`数组中使用`map`函数为每个错误渲染一个`span`。

1.  我们已经引用了一个 CSS `form-error`类，所以让我们把它添加到`index.css`中：

```jsx
.form-error {
  font-size: 13px;
  color: red;
  margin: 3px auto 0px 0px;
}
```

现在是时候尝试联系我们页面了。如果我们的应用程序没有启动，请使用`npm start`启动它，然后转到联系我们页面。如果我们通过名称和电子邮件字段进行切换，将触发必填验证规则，并显示错误消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5c1c0bd5-41d7-4dfe-a583-681a209e50fd.png)

这正是我们想要的。如果我们回到名称字段，尝试在切换之前只输入一个字符，那么最小长度验证错误会触发，正如我们所期望的那样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/985e637e-04be-4016-ba1f-990898bada01.png)

我们的通用表单组件现在几乎完成了。我们的最后任务是提交表单，我们将在下一节中完成。

# 表单提交

提交表单是表单实现的最后一部分。`Form`组件的消费者将处理实际的提交，这可能会导致调用 Web API。我们的`Form`组件在表单提交时将简单地调用消费者代码中的一个函数。

# 在表单中添加一个提交按钮

在这一节中，我们将向我们的`Form`组件添加一个提交按钮：

1.  让我们在`Form` JSX 中添加一个提交按钮，放在`form-group`中的`div`容器中：

```jsx
<FormContext.Provider value={context}>
  <form className="form" noValidate={true}>
    {this.props.children}
    <div className="form-group">
 <button type="submit">Submit</button>
 </div>
  </form>
</FormContext.Provider>
```

1.  使用以下 CSS 样式为按钮添加样式在`index.css`中：

```jsx
.form-group button {
  font-size: 16px;
  padding: 8px 5px;
  width: 80px;
  border: black solid 1px;
  border-radius: 5px;
  background-color: black;
  color: white;
}
.form-group button:disabled {
  border: gray solid 1px;
  background-color: gray;
  cursor: not-allowed;
}
```

我们现在在表单上有一个黑色的提交按钮，当禁用时是灰色的。

# 添加一个 onSubmit 表单 prop

在我们的`Form`组件中，我们需要一个新的 prop，允许消费者指定要调用的`submit`函数。我们将在这一节中完成这个任务：

1.  让我们首先在`Form` props 接口中创建一个名为`onSubmit`的新 prop 函数：

```jsx
export interface ISubmitResult {
 success: boolean;
 errors?: IErrors;
}

interface IFormProps {
  defaultValues: IValues;
  validationRules: IValidationProp;
  onSubmit: (values: IValues) => Promise<ISubmitResult>;
}
```

该函数将接受字段值，并异步返回提交是否成功，以及在服务器上发生的任何验证错误。

1.  我们将跟踪表单是否正在提交或者在 `Form` 状态中成功提交的情况。

```jsx
interface IState {
  values: IValues;
  errors: IErrors;
  submitting: boolean;
 submitted: boolean;
}
```

1.  让我们在构造函数中初始化这些状态值：

```jsx
constructor(props: IFormProps) {
  ...
  this.state = {
    errors,
    submitted: false,
 submitting: false,
    values: props.defaultValues
  };
}
```

1.  如果表单正在提交或已成功提交，我们现在可以禁用提交按钮：

```jsx
<button
  type="submit"
  disabled={this.state.submitting || this.state.submitted}
>
  Submit
</button>
```

1.  让我们在 `form` 标签中引用一个提交处理程序：

```jsx
<form className="form" noValidate={true} onSubmit={this.handleSubmit}>
  ...
</form>
```

1.  现在我们可以开始实现我们刚刚引用的提交处理程序：

```jsx
private handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();

};
```

我们在提交事件参数中调用 `preventDefault` 来阻止浏览器自动发布表单。

1.  在开始表单提交过程之前，我们需要确保所有字段都是有效的。让我们引用并创建一个执行此操作的 `validateForm` 函数：

```jsx
private validateForm(): boolean {
 const errors: IErrors = {};
 let haveError: boolean = false;
 Object.keys(this.props.defaultValues).map(fieldName => {
 errors[fieldName] = this.validate(
 fieldName,
 this.state.values[fieldName]
 );
 if (errors[fieldName].length > 0) {
 haveError = true;
 }
 });
 this.setState({ errors });
 return !haveError;
}

private handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();
  if (this.validateForm()) {

 }
};
```

`validateForm` 函数遍历字段，调用已经实现的 `validate` 函数。状态会更新为最新的验证错误，并返回字段中是否有任何错误。

1.  让我们现在实现剩下的提交处理程序：

```jsx
private handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
  e.preventDefault();
  if (this.validateForm()) {
    this.setState({ submitting: true });
 const result = await this.props.onSubmit(this.state.values);
 this.setState({
 errors: result.errors || {},
 submitted: result.success,
 submitting: false
 });
  }
};
```

如果表单有效，我们首先将 `submitting` 状态设置为 `true`。然后我们异步调用 `onSubmit` prop 函数。当 `onSubmit` prop 函数完成时，我们将函数中的任何验证错误与提交是否成功一起设置在状态中。我们还在状态中设置提交过程已经完成的事实。

现在，我们的 `Form` 组件有一个 `onSubmit` 函数 prop。在下一节中，我们将在我们的联系我们页面中使用它。

# 使用 onSubmit 表单 prop

在这一节中，我们将在 `ContactUs` 组件中使用 `onSubmit` 表单 prop。`ContactUs` 组件不会管理提交，它只会委托给 `ContactUsPage` 组件来处理提交：

1.  让我们首先导入 `ISubmitResult` 和 `IValues`，并在 `ContactUs` 组件中为 `onSubmit` 函数创建一个 props 接口：

```jsx
import { Form, ISubmitResult, IValues, minLength, required } from "./Form";

interface IProps {
 onSubmit: (values: IValues) => Promise<ISubmitResult>;
} const ContactUs: React.SFC<IProps> = props => { ... }
```

1.  创建一个 `handleSubmit` 函数来调用 `onSubmit` prop：

```jsx
const ContactUs: React.SFC<IProps> = props => {
  const handleSubmit = async (values: IValues): Promise<ISubmitResult> => {
 const result = await props.onSubmit(values);
 return result;
 };
  return ( ... );
};
```

`onSubmit` prop 是异步的，所以我们需要在我们的函数前加上 `async`，并在 `onSubmit` 调用前加上 `await`。

1.  在 JSX 中将此提交处理程序绑定到表单的 `onSubmit` prop 中：

```jsx
return (
  <Form ... onSubmit={handleSubmit}>
    ...
  </Form>
);
```

1.  现在让我们转到 `ContactUsPage` 组件。让我们首先创建提交处理程序：

```jsx
private handleSubmit = async (values: IValues): Promise<ISubmitResult> => {
  await wait(1000); // simulate asynchronous web API call
  return {
    errors: {
      email: ["Some is wrong with this"]
    },
    success: false
  };
};
```

在实践中，这可能会调用一个 web API。在我们的例子中，我们异步等待一秒钟，并返回一个带有 `email` 字段的验证错误。

1.  让我们创建刚刚引用的 `wait` 函数：

```jsx
const wait = (ms: number): Promise<void> => {
 return new Promise(resolve => setTimeout(resolve, ms));
};
```

1.  现在让我们将`handleSubmit`方法与`ContactUs`的`onSubmit`属性连接起来：

```jsx
<ContactUs onSubmit={this.handleSubmit} />
```

1.  我们已经引用了`IValues`和`ISubmitResult`，所以让我们导入它们：

```jsx
import { ISubmitResult, IValues } from "./Form";
```

如果我们转到正在运行的应用程序中的联系我们页面，填写表单并单击提交按钮，我们会收到有关电子邮件字段存在问题的通知，这是我们所期望的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5f19c687-47c8-4ade-b729-bb59fccf669d.png)

1.  让我们将`ContactUsPage`中的提交处理程序更改为返回成功的结果：

```jsx
private handleSubmit = async (values: IValues): Promise<ISubmitResult> => {
  await wait(1000); // simulate asynchronous web API call
 return {
 success: true
 };
};
```

现在，如果我们再次转到正在运行的应用程序中的联系我们页面，填写表单并单击提交按钮，提交将顺利进行，并且提交按钮将被禁用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/dc82f431-136d-484c-b5e2-c3b86a943fa8.png)

因此，我们的联系我们页面已经完成，还有我们的通用`Form`和`Field`组件。

# 总结

在本章中，我们讨论了受控组件，这是 React 处理表单数据输入的推荐方法。通过受控组件，我们让 React 通过组件状态控制输入值。

我们研究了构建通用的`Form`和`Field`组件，这些组件包含状态和更改处理程序，因此我们不需要为应用程序中每个表单中的每个字段实现单独的状态和更改处理程序。

然后，我们创建了一些标准验证函数，并在通用`Form`组件中添加了添加验证规则的能力，并在`Field`组件中自动呈现验证错误。

最后，我们添加了在使用通用`Form`组件时处理表单提交的能力。我们的联系我们页面已更改为使用通用的`Form`和`Field`组件。

我们的通用组件只处理非常简单的表单。毫不奇怪，已经有相当多的成熟表单库在外面。一个受欢迎的选择是 Formik，它在某些方面类似于我们刚刚构建的内容，但功能更加强大。

如果您正在构建包含大量表单的应用程序，构建一个通用表单或使用 Formik 等已建立的库来加快开发过程是非常值得的。

# 问题

通过尝试以下实现来检查关于 React 和 TypeScript 中表单的所有信息是否已经掌握：

1.  扩展我们的通用`Field`组件，使用原生数字输入包括一个数字编辑器。

1.  在联系我们表单上实现一个紧急性字段，以指示回复的紧急程度。该字段应为数字。

1.  在通用的`Form`组件中实现一个新的验证器函数，用于验证一个数字是否落在另外两个数字之间。

1.  在紧急字段上实施验证规则，以确保输入是 1 到 10 之间的数字。

1.  我们的验证在用户点击字段而不输入任何内容时触发。当字段失去焦点时如何触发验证，但只有在字段已经被更改时？

# 进一步阅读

以下链接是关于 React 中表单的进一步信息的良好来源：

+   在 React 文档中有一个关于表单的部分，网址是[`reactjs.org/docs/forms.html`](https://reactjs.org/docs/forms.html)。

+   Formik 库是值得深入研究的。可以在[`github.com/jaredpalmer/formik`](https://github.com/jaredpalmer/formik)找到。
