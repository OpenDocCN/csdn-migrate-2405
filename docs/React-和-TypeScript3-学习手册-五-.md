# React 和 TypeScript3 学习手册（五）

> 原文：[`zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487`](https://zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：React Redux

到目前为止，在本书中，我们已经在 React 组件内部管理了状态。当状态需要在不同组件之间共享时，我们还使用了 React 上下文。这种方法对许多应用程序都很有效。React Redux 帮助我们强大地处理复杂的状态场景。当用户交互导致状态发生多个变化时，它会发挥作用，也许其中一些是有条件的，特别是当交互导致 web 服务调用时。当应用程序中存在大量共享状态时，它也非常有用。

在本章中，我们将继续构建我们的 React 商店，添加 React Redux 来帮助我们管理状态交互。最终，我们将在商店的页眉中添加一个购物篮摘要组件，通知用户他们的购物篮中有多少件商品。Redux 将帮助我们在商品添加到购物篮时更新此组件。

在本章的最后一节中，我们将探讨一种类似于 Redux 的方法，用于在组件内部管理复杂状态。这是在 Redux 存储中管理状态和仅在组件内部使用`setState`或`useState`之间的中间地带。

在本章中，我们将学习以下主题：

+   原则和关键概念

+   安装 Redux

+   创建 reducers

+   创建动作

+   创建存储

+   将我们的 React 应用连接到存储

+   使用 useReducer 管理状态

# 技术要求

在本章中，我们将使用以下技术：

+   **Node.js 和** `npm`：TypeScript 和 React 依赖于这些。我们可以从[`nodejs.org/en/download/`](https://nodejs.org/en/download/)安装这些。如果我们已经安装了这些，请确保`npm`至少是 5.2 版本。

+   **Visual Studio Code**：我们需要一个编辑器来编写我们的 React 和 TypeScript 代码，可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)安装。我们还需要在 Visual Studio Code 中安装 TSLint（由 egamma 提供）和 Prettier（由 Estben Petersen 提供）扩展。

+   **React 商店**：我们将从上一章完成的 React 商店项目开始。该项目可以在 GitHub 上找到[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/07-WorkingWithForms/04-FormSubmission`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/07-WorkingWithForms/04-FormSubmission)。

为了从上一章恢复代码，可以下载[`github.com/carlrip/LearnReact17WithTypeScript`](https://github.com/carlrip/LearnReact17WithTypeScript)上的`LearnReact17WithTypeScript`存储库。然后可以在 Visual Studio Code 中打开相关文件夹，然后在终端中输入`npm install`进行恢复。本章中的所有代码片段都可以在[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/08-ReactRedux%EF%BB%BF`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/08-ReactRedux%EF%BB%BF)上找到。

# 原则和关键概念

在本节中，我们将首先介绍 Redux 中的三个原则，然后深入探讨核心概念。

# 原则

让我们来看看 Redux 的三个原则：

+   **唯一数据源**：这意味着整个应用程序状态存储在一个对象中。在真实的应用程序中，该对象可能包含复杂的嵌套对象树。

+   **状态是只读的**：这意味着状态不能直接更改。这有点像说我们不能直接更改组件内的状态。在 Redux 中，更改状态的唯一方法是分派所谓的动作。

+   更改是通过纯函数进行的：负责更改状态的函数称为 reducers。

在接下来的章节中，我们将更深入地了解动作和 reducers，以及管理它们的东西，即所谓的**store**。

# 关键概念

应用程序的整个状态存储在所谓的**store**中。状态存储在一个 JavaScript 对象中，如下所示：

```jsx
{
  products: [{ id: 1, name: "Table", ...}, {...}, ...],
  productsLoading: false,
  currentProduct: { id: 2, xname: "Chair", ... },
  basket: [{ product: { id: 2, xname: "Chair" }, quantity: 1 }],
};
```

在这个例子中，单个对象包含以下内容：

+   产品数组

+   产品是否正在从 Web API 中获取

+   用户正在查看的当前产品

+   用户购物篮中的物品

状态不包含任何函数、设置器或任何获取器。它是一个简单的 JavaScript 对象。存储还协调 Redux 中的所有移动部分。这包括通过 reducers 推送动作来更新状态。

因此，要更新存储中的状态，首先需要分派一个**action**。动作是另一个简单的 JavaScript 对象，如下所示：

```jsx
{
  type: "PRODUCTS/LOADING"
}
```

`type`属性确定需要执行的操作类型。这是操作的一个重要且必需的部分。如果操作对象中没有`type`，reducer 将不知道如何更改状态。在前面的示例中，操作除了`type`属性之外没有包含任何其他内容。这是因为 reducer 不需要其他信息来为此类型的操作更改状态。

以下示例是另一个操作：

```jsx
{
  type: "PRODUCTS/GETSINGLE",
  product: { id: 1, name: "Table", ...}
}
```

这次，在操作中包含了一个`product`属性的额外信息。reducer 需要这些额外信息来为此类型的操作更改状态。

因此，reducer 是实际更改状态的纯函数。

纯函数对于给定的一组参数总是返回相同的结果。因此，这些函数不依赖于函数范围之外的任何状态，而这些状态没有传递到函数中。纯函数也不会改变函数范围之外的任何状态。

以下是 reducer 的一个示例：

```jsx
export const productsReducer = (state = initialProductState, action) => {
  switch (action.type) {
    case "PRODUCTS/LOADING": {
      return {
        ...state,
        productsLoading: true
      };
    }
    case "PRODUCTS/GETSINGLE": {
      return {
        ...state,
        currentProduct: action.product,
        productsLoading: false
      };
    }
    default:
  }
  return state || initialProductState;
};
```

以下是关于 reducer 的一些内容：

+   reducer 接受当前状态和正在执行的操作这两个参数。

+   当首次调用 reducer 时，状态参数默认为初始状态对象

+   在操作类型上使用 switch 语句，并为其每个分支创建一个新的状态对象

+   为了创建新状态，我们将当前状态扩展到一个新对象中，然后用已更改的属性覆盖它

+   新状态是从 reducer 返回的

您会注意到我们刚刚看到的操作和 reducer 没有 TypeScript 类型。显然，在我们在接下来的章节中实现这些时，我们将包含必要的类型。

因此，现在我们已经开始了解 Redux 是什么，是时候在我们的 React 商店中实践这一点了。

# 安装 Redux

在我们可以使用 Redux 之前，我们需要安装它以及 TypeScript 类型。我们还将安装一个名为`redux-thunk`的额外库，这是为了实现异步操作而需要的：

1.  如果我们还没有的话，让我们从上一章结束的地方在 Visual Studio Code 中打开我们的 React 商店项目。因此，让我们在终端中通过`npm`安装核心 Redux 库：

```jsx
npm install redux
```

请注意，核心 Redux 库中包含了 TypeScript 类型。因此，不需要额外安装这些类型。

1.  让我们现在安装 Redux 的 React 特定部分。这些部分允许我们将 React 组件连接到 Redux 存储。让我们通过`npm`安装这些部分：

```jsx
npm install react-redux
```

1.  让我们也安装`react-redux`的 TypeScript 类型：

```jsx
npm install --save-dev @types/react-redux
```

1.  让我们也安装`redux-thunk`：

```jsx
npm install redux-thunk
```

1.  最后，我们可以安装`redux-thunk`的 TypeScript 类型：

```jsx
npm install --save-dev @types/redux-thunk
```

现在所有 Redux 部分都已安装，我们可以在下一节中将 Redux 添加到我们一直在开发的 React 商店中。

# 创建操作

我们将扩展我们在之前章节中构建的 React 商店，并添加 Redux 来管理`Products`页面上的状态。在本节中，我们将创建操作来开始将产品添加到页面的过程。将有一个操作来获取产品。将有另一个操作来改变一些新的加载状态，最终我们将把它与我们项目中已经拥有的`withLoading` HOC 联系起来。

在我们开始编写 Redux 操作之前，让我们在`ProductsData.ts`中创建一个虚拟 API 来获取产品：

```jsx
export const getProducts = async (): Promise<IProduct[]> => {
  await wait(1000);
  return products;
};
```

因此，该函数在返回产品之前会异步等待一秒钟。

我们需要通过创建一些类型来开始实现我们的操作。我们将在下一步完成这个步骤。

# 创建状态和操作类型

现在是时候开始使用 Redux 来增强我们的 React 商店了。我们将首先为 Redux 存储创建一些状态和操作类型：

1.  让我们在`src`文件夹中创建一个名为`ProductsTypes.ts`的新文件，并在顶部添加以下导入语句：

```jsx
import { IProduct } from "./ProductsData";
```

1.  让我们为我们将要实现的两种不同操作类型创建一个枚举：

```jsx
export enum ProductsActionTypes {
  GETALL = "PRODUCTS/GETALL",
  LOADING = "PRODUCTS/LOADING"
}
```

Redux 不规定操作类型字符串的格式。因此，操作类型字符串的格式是我们的选择。但是，我们需要确保这些字符串在存储中的操作类型中是唯一的。因此，我们在字符串中包含了两个信息：

+   操作涉及的存储区域。在我们的情况下，这是`PRODUCTS`。

+   该区域内的特定操作。在我们的情况下，我们有`GETALL`用于获取所有产品，`LOADING`用于指示产品正在被获取。

我们可以选择`PRODUCTS`-`GETALL`或`Get All Products`。我们只需要确保字符串是唯一的。我们使用枚举来在实现操作和减速器时给我们良好的 IntelliSense。

1.  现在我们可以为这两个操作创建接口：

```jsx
export interface IProductsGetAllAction {
  type: ProductsActionTypes.GETALL,
  products: IProduct[]
}

export interface IProductsLoadingAction {
  type: ProductsActionTypes.LOADING
}
```

`IProductsGetAllAction`接口用于在需要获取产品时分派的动作。`IProductsLoadingAction`接口用于导致减速器改变加载状态的动作。

1.  让我们将动作类型与联合类型结合在一起：

```jsx
export type ProductsActions =
  | IProductsGetAllAction
  | IProductsLoadingAction
```

这将是传递给减速器的动作参数的类型。

1.  最后，让我们在存储中为这个状态区域创建一个接口：

```jsx
export interface IProductsState {
  readonly products: IProduct[];
  readonly productsLoading: boolean;
}
```

因此，我们的状态将包含一个产品数组，以及产品是否正在加载。

请注意，属性前缀带有`readonly`关键字。这将帮助我们避免直接更改状态。

现在我们已经为动作和状态准备好了类型，我们可以在下一节中创建一些动作。

# 创建动作

在这一节中，我们将创建两个动作，用于获取产品并指示产品正在加载。

1.  让我们从创建一个带有以下导入语句的`ProductsActions.ts`文件开始：

```jsx
import { ActionCreator, AnyAction, Dispatch } from "redux";
```

这些是我们在实现动作时将要使用的 Redux 中的一些类型。

1.  我们的动作之一将是异步的。因此，让我们从`redux-thunk`中导入一个类型，以便在实现此动作时准备好：

```jsx
import { ThunkAction } from "redux-thunk";
```

1.  让我们添加另一个导入语句，以便我们可以使用我们的虚假 API：

```jsx
import { getProducts as getProductsFromAPI } from "./ProductsData";
```

我们将 API 函数重命名为`getProductsFromAPI`，以避免名称冲突，因为我们将稍后创建一个名为`getProducts`的动作。

1.  让我们还导入上一节中创建的类型：

```jsx
import { IProductsGetAllAction, IProductsLoadingAction, IProductsState, ProductsActionTypes } from "./ProductsTypes";
```

1.  我们现在要创建一个称为动作创建者的东西。动作创建者就像它的名字一样：它是一个创建并返回动作的函数！让我们为创建产品加载动作创建一个动作创建者：

```jsx
const loading: ActionCreator<IProductsLoadingAction> = () => {
  return {
    type: ProductsActionTypes.LOADING
  }
};
```

+   我们使用包含适当动作接口的泛型`ActionCreator`类型来定义函数签名

+   该函数简单地返回所需的动作对象

我们可以使用隐式返回语句更简洁地编写这个函数，如下所示：

```jsx
const loading: ActionCreator<IProductsLoadingAction> = () => ({
  type: ProductsActionTypes.LOADING
});
```

在实现动作创建者时，我们将使用这种更短的语法。

1.  让我们继续实现获取产品的动作创建者。这更复杂，所以让我们从函数签名开始：

```jsx
export const getProducts: ActionCreator<ThunkAction<Promise<AnyAction>, IProductsState, null, IProductsGetAllAction>> = () => {};
```

我们再次使用泛型`ActionCreator`类型，但这次它包含的不仅仅是最终返回的动作接口。这是因为这个特定的动作是异步的。

我们在`ActionCreator`中使用`ThunkAction`进行异步操作，这是一个具有四个参数的泛型类型：

+   第一个参数是返回类型，理想情况下应该是`Promise<IProductsGetAllAction>`。但是，TypeScript 编译器很难解析这一点，因此我们选择了稍微宽松一些的`Promise<AnyAction>`类型。

+   第二个参数是动作所关注的状态接口。

+   第三个参数是传递给动作创建者的参数类型，在我们的情况下是`null`，因为没有参数。

+   最后一个参数是动作的类型。

我们导出此动作创建者，因为最终将从`ProductsPage`组件中调用它。

1.  异步动作需要返回一个最终会分派我们的动作的异步函数：

```jsx
export const getProducts: ActionCreator<ThunkAction<Promise<AnyAction>, IProductsState, null, IProductsGetAllAction>> = () => {
  return async (dispatch: Dispatch) => {

 };
};
```

因此，该函数的第一件事是返回另一个函数，使用`async`关键字标记为异步。内部函数将调度程序从存储中作为参数。

1.  让我们实现内部函数：

```jsx
return async (dispatch: Dispatch) => {
  dispatch(loading());
 const products = await getProductsFromAPI();
 return dispatch({
 products,
 type: ProductsActionTypes.GETALL
 });
};
```

+   我们首先要做的是分派另一个动作，以便加载状态最终由 reducer 相应地更改

+   下一步是从虚拟 API 异步获取产品

+   最后一步是分派所需的动作

现在我们已经创建了一些动作，我们将在下一节中创建一个 reducer。

# 创建 reducer

Reducer 是一个负责为给定动作创建新状态的函数。因此，该函数接受当前状态的动作，并返回新状态。在本节中，我们将为产品创建两个动作的 reducer。

1.  让我们从创建一个名为`ProductsReducer.ts`的文件开始，其中包含以下导入语句：

```jsx
import { Reducer } from "redux";
import { IProductsState, ProductsActions, ProductsActionTypes } from "./ProductsTypes";
```

我们从 Redux 中导入`Reducer`类型以及我们之前创建的动作和状态的类型。

1.  接下来，我们需要定义初始状态是什么：

```jsx
const initialProductState: IProductsState = {
  products: [],
  productsLoading: false
};
```

因此，我们将产品设置为空数组，并将产品加载状态设置为`false`。

1.  我们现在可以开始创建 reducer 函数：

```jsx
export const productsReducer: Reducer<IProductsState, ProductsActions> = (
  state = initialProductState,
  action
) => {
 switch (action.type) {
  // TODO - change the state
 }
 return state;
};
```

+   我们使用 Redux 的`Reducer`泛型类型对函数进行了类型化，传入了我们的状态和动作类型。这为我们提供了很好的类型安全性。

+   该函数根据 Redux 所需的状态和动作参数。

+   状态默认为我们在上一步中设置的初始状态对象。

+   在函数的最后，如果动作类型在 switch 语句中没有被识别，我们将返回默认状态。

1.  让我们继续实现我们的 reducer：

```jsx
switch (action.type) {
  case ProductsActionTypes.LOADING: {
 return {
 ...state,
 productsLoading: true
 };
 }
 case ProductsActionTypes.GETALL: {
 return {
 ...state,
 products: action.products,
 productsLoading: false
 };
 }
}
```

我们为每个 action 实现了一个 switch 分支。两个分支都遵循相同的模式，通过返回一个新的状态对象，其中包含旧状态并合并了适当的属性。

这是我们的第一个 reducer 完成。在下一节中，我们将创建我们的 store。

# 创建一个 store

在本节中，我们将创建一个 store，用于保存我们的状态并管理动作和 reducer：

1.  让我们首先创建一个名为`Store.tsx`的新文件，并使用以下导入语句从 Redux 中获取我们需要的部分：

```jsx
import { applyMiddleware, combineReducers, createStore, Store } from "redux";
```

+   `createStore`是一个我们最终将用来创建我们的 store 的函数

+   我们需要`applyMiddleware`函数，因为我们需要使用 Redux Thunk 中间件来管理我们的异步动作

+   `combineReducers`函数是一个我们可以用来合并我们的 reducers 的函数

+   `Store`是一个我们可以用于 store 的 TypeScript 类型

1.  让我们导入`redux-thunk`：

```jsx
import thunk from "redux-thunk";
```

1.  最后，让我们导入我们的 reducer 和状态类型：

```jsx
import { productsReducer } from "./ProductsReducer";
import { IProductsState } from "./ProductsTypes";
```

1.  store 的一个关键部分是状态。因此，让我们为此定义一个接口：

```jsx
export interface IApplicationState {
  products: IProductsState;
}
```

此时，接口只包含了我们的产品状态。

1.  现在让我们把我们的 reducer 放到 Redux 的`combineReducer`函数中：

```jsx
const rootReducer = combineReducers<IApplicationState>({
  products: productsReducer
});
```

1.  有了状态和根 reducer 定义，我们可以创建我们的 store。实际上，我们要创建一个创建 store 的函数：

```jsx
export default function configureStore(): Store<IApplicationState> {
  const store = createStore(rootReducer, undefined, applyMiddleware(thunk));
  return store;
}
```

+   创建我们的 store 的函数被称为`configureStore`，并返回具有特定 store 状态的通用`Store`类型。

+   该函数使用 Redux 的`createStore`函数来创建并返回 store。我们传入我们的 reducer 以及 Redux Thunk 中间件。我们将`undefined`作为初始状态，因为我们的 reducer 会处理初始状态。

我们已经在我们的 store 上取得了很好的进展。在下一节中，我们将开始连接我们的 React 商店到我们的 store。

# 将我们的 React 应用连接到 store。

在本节中，我们将连接`Products`页面到我们的 store。第一步是添加 React Redux 的`Provider`组件，我们将在下一节中完成。

# 添加 store Provider 组件

`Provider`组件可以将 store 传递给其下的任何级别的组件。因此，在本节中，我们将在组件层次结构的顶部添加`Provider`，以便所有我们的组件都可以访问它：

1.  让我们打开我们现有的`index.tsx`并从 React Redux 中导入`Provider`组件：

```jsx
import { Provider} from "react-redux";
```

1.  让我们还从 React Redux 中导入`Store`类型：

```jsx
import { Store } from "redux";
```

1.  我们需要从我们的商店中导入以下内容：

```jsx
import configureStore from "./Store";
import { IApplicationState } from "./Store";
```

1.  然后我们将在导入语句之后创建一个小的函数组件：

```jsx
interface IProps {
  store: Store<IApplicationState>;
}
const Root: React.SFC<IProps> = props => {
  return ();
};
```

这个`Root`组件将成为我们的新根元素。它将我们的商店作为一个 prop。

1.  因此，我们需要在我们的新根组件中包含旧的根元素`Routes`：

```jsx
const Root: React.SFC<IProps> = props => {
  return (
    <Routes />
  );
};
```

1.  这个组件还需要添加另一件事，那就是来自 React Redux 的`Provider`组件：

```jsx
return (
  <Provider store={props.store}>
    <Routes />
  </Provider>
);
```

我们已经将`Provider`放在了组件树的顶部，并将我们的商店传递给它。

1.  完成我们的新根组件后，让我们更改我们的根渲染函数：

```jsx
const store = configureStore();
ReactDOM.render(<Root store={store} />, document.getElementById(
  "root"
) as HTMLElement);
```

我们首先使用我们的`configureStore`函数创建商店，然后将其传递给我们的`Root`组件。

因此，这是将我们的组件连接到商店的第一步。在下一节中，我们将完成对`ProductPage`组件的连接。

# 将组件连接到商店

我们即将看到我们增强的商店在行动中。在本节中，我们将连接我们的商店到几个组件。

# 将 ProductsPage 连接到商店

我们要连接到商店的第一个组件将是`ProductsPage`组件。

让我们打开`ProductsPage.tsx`并开始重构它：

1.  首先，让我们从 React Redux 中导入`connect`函数：

```jsx
import { connect } from "react-redux";
```

我们将在本节末尾使用`connect`函数将`ProductsPage`组件连接到商店。

1.  让我们从我们的商店中导入存储状态类型和`getProducts`动作创建者：

```jsx
import { IApplicationState } from "./Store";
import { getProducts } from "./ProductsActions";
```

1.  `ProductPage`组件现在不会包含任何状态，因为这将保存在 Redux 存储中。因此，让我们首先删除状态接口、静态`getDerivedStateFromProps`方法，以及构造函数。`ProductsPage`组件现在应该具有以下形状：

```jsx
class ProductsPage extends React.Component<RouteComponentProps> {
  public async componentDidMount() { ... }
  public render() { ... }
}
```

1.  现在，数据将通过 props 从商店中获取。因此，让我们重构我们的 props 接口：

```jsx
interface IProps extends RouteComponentProps {
 getProducts: typeof getProducts;
 loading: boolean;
 products: IProduct[];
}

class ProductsPage extends React.Component<IProps> { ... }
```

因此，我们将从商店传递以下数据到我们的组件：

+   `getProducts`动作创建者

+   一个名为`loading`的标志，指示产品是否正在被获取

+   产品数组

1.  因此，让我们调整`componentDidMount`生命周期方法，以调用`getProducts`动作创建者来开始获取产品的过程：

```jsx
public componentDidMount() {
  this.props.getProducts();
}
```

1.  我们不再直接引用`ProductsData.ts`中的`products`数组。因此，让我们从输入语句中删除它，使其如下所示：

```jsx
import { IProduct } from "./ProductsData";
```

1.  我们仍然看不到我们以前使用的`search`状态。现在我们将在`render`方法开始时获取它，而不是在状态中存储它：

```jsx
public render() {
  const searchParams = new URLSearchParams(this.props.location.search);
 const search = searchParams.get("search") || "";
  return ( ... );
}
```

1.  让我们留在`render`方法中，替换旧的`state`引用：

```jsx
<ul className="product-list">
  {this.props.products.map(product => {
    if (!search || (search && product.name.toLowerCase().indexOf(search.toLowerCase()) > -1)
    ) { ... }
  })}
</ul>
```

1.  在类下面，但在导出语句之前，让我们创建一个函数，将来自存储的状态映射到组件属性：

```jsx
const mapStateToProps = (store: IApplicationState) => {
  return {
    loading: store.products.productsLoading,
    products: store.products.products
  };
};
```

因此，我们正在获取产品是否正在加载以及从存储中获取这些产品并将它们传递给我们的 props。

1.  我们还需要映射到另一个 prop，那就是`getProducts`函数 prop。让我们创建另一个函数，将这个操作从存储映射到组件中的函数 prop：

```jsx
const mapDispatchToProps = (dispatch: any) => {
  return {
    getProducts: () => dispatch(getProducts())
  };
};
```

1.  在文件底部还有一项工作要做。这是在导出之前，将 React Redux 的`connect` HOC 包装在我们的`ProductsPage`组件周围：

```jsx
export default connect(
 mapStateToProps,
 mapDispatchToProps
)(ProductsPage);
```

`connect` HOC 将组件连接到我们的存储，这是由组件树中更高级别的`Provider`组件提供给我们的。`connect` HOC 还调用映射函数，将存储中的状态和操作创建者映射到组件属性中。

1.  现在终于是时候尝试我们增强的页面了。让我们通过终端启动开发服务器和应用程序：

```jsx
npm start
```

我们应该发现页面的行为与以前完全相同。唯一的区别是现在状态是在我们的 Redux 存储中管理的。

在下一节中，我们将通过添加我们项目中已经拥有的加载旋转器来增强我们的产品页面。

# 将 ProductsPage 连接到加载存储状态。

在本节中，我们将向产品页面添加一个加载旋转器。在此之前，我们将把产品列表提取到自己的组件中。然后我们可以将`withLoader` HOC 添加到提取的组件中：

1.  让我们为提取的组件创建一个名为`ProductsList.tsx`的新文件，并导入以下内容：

```jsx
import * as React from "react";
import { Link } from "react-router-dom";
import { IProduct } from "./ProductsData";
import withLoader from "./withLoader";
```

1.  该组件将接受产品数组和搜索字符串的 props：

```jsx
interface IProps {
  products?: IProduct[];
  search: string;
}
```

1.  我们将称该组件为`ProductList`，它将是一个 SFC。让我们开始创建组件：

```jsx
const ProductsList: React.SFC<IProps> = props => {
  const search = props.search;
  return ();
};
```

1.  现在我们可以将`ProductsPage`组件 JSX 中的`ul`标签移动到我们新的`ProductList`组件的返回语句中：

```jsx
return (
  <ul className="product-list">
    {props.products &&
      props.products.map(product => {
        if (
          !search ||
          (search &&
            product.name.toLowerCase().indexOf(search.toLowerCase()) 
            > -1)
        ) {
          return (
            <li key={product.id} className="product-list-item">
              <Link to={`/products/${product.id}`}>{product.name}
              </Link>
            </li>
          );
        } else {
          return null;
        }
      })}
  </ul>
);
```

请注意，在移动 JSX 后，我们会删除对`this`的引用。

1.  完成`ProductList`组件后，让我们将其导出并使用我们的`withLoader`HOC 包装：

```jsx
export default withLoader(ProductsList);
```

1.  让我们更改`ProductPage.tsx`中的返回语句以引用提取的组件：

```jsx
return (
  <div className="page-container">
    <p>
      Welcome to React Shop where you can get all your tools for ReactJS!
    </p>
    <ProductsList
 search={search}
 products={this.props.products}
 loading={this.props.loading}
 />
  </div>
);
```

1.  我们不要忘记引入已引用的`ProductsList`组件：

```jsx
import ProductsList from "./ProductsList";
```

1.  最后，我们可以在`ProductsPage.tsx`中删除导入的`Link`组件，因为它不再被引用。

如果我们转到正在运行的应用程序并浏览到产品页面，我们现在应该看到产品加载时的加载旋转器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/85661d16-f25f-49f0-a37c-ba5ffde733ba.png)

因此，我们的产品页面现在已经很好地连接到了 Redux 存储。在下一节中，我们将把产品页面连接到存储。

# 将产品状态和操作添加到存储

将`ProductPage`组件连接到我们的存储首先需要在我们的存储中进行一些工作。我们需要额外的状态来存储当前产品，以及它是否已添加到购物篮中。我们还需要额外的操作和减速器代码来获取产品并将其添加到购物篮中：

1.  首先，在`ProductsTypes.ts`中为当前产品添加额外的状态：

```jsx
export interface IProductsState {
  readonly currentProduct: IProduct | null;
  ...
}
```

1.  当我们在`ProductTypes.ts`中时，让我们添加获取产品的操作类型：

```jsx
export enum ProductsActionTypes {
  GETALL = "PRODUCTS/GETALL",
  GETSINGLE = "PRODUCTS/GETSINGLE",
  LOADING = "PRODUCTS/LOADING"
}
```

1.  让我们还为获取产品添加操作类型：

```jsx
export interface IProductsGetSingleAction {
  type: ProductsActionTypes.GETSINGLE;
  product: IProduct;
}
```

1.  然后，我们可以将此操作类型添加到我们的联合操作类型中：

```jsx
export type ProductsActions = IProductsGetAllAction| IProductsGetSingleAction | IProductsLoadingAction;
```

1.  让我们继续在`ProductsActions.ts`中创建新的操作创建者。首先，让我们导入我们的虚假 API 以获取产品：

```jsx
import { getProduct as getProductFromAPI, getProducts as getProductsFromAPI} from "./ProductsData";
```

1.  然后我们可以导入我们需要实现的操作创建者的类型：

```jsx
import { IProductsGetAllAction, IProductsGetSingleAction, IProductsLoadingAction, IProductsState, ProductsActionTypes } from "./productsTypes";
```

1.  让我们实现获取产品的操作创建者：

```jsx
export const getProduct: ActionCreator<ThunkAction<Promise<any>, IProductsState, null, IProductsGetSingleAction>> = (id: number) => {
  return async (dispatch: Dispatch) => {
    dispatch(loading());
    const product = await getProductFromAPI(id);
    dispatch({
      product,
      type: ProductsActionTypes.GETSINGLE
    });
  };
};
```

这与`getProducts`操作创建者非常相似。结构上唯一的区别是操作创建者接受产品 ID 的参数。

1.  现在转到`ProductsReducer.ts`中的减速器。首先在初始状态中将当前产品设置为 null：

```jsx
const initialProductState: IProductsState = {
  currentProduct: null,
  ...
};
```

1.  在`productReducer`函数中，让我们为我们的新操作类型在 switch 语句中添加一个分支：

```jsx
switch (action.type) {
  ...
  case ProductsActionTypes.GETSINGLE: {
 return {
 ...state,
 currentProduct: action.product,
 productsLoading: false
 };
 }
}
```

我们将旧状态扩展到一个新对象中，覆盖当前项目，并将加载状态设置为`false`。

因此，这是产品页面在 Redux 存储中需要的一些状态管理。但是，我们还没有在我们的存储中管理购物篮。我们将在下一节中完成这一点。

# 将购物篮状态和操作添加到存储中

在这一部分，我们将为我们的购物篮添加状态管理。我们将在我们的存储中创建一个新的部分。

1.  首先，让我们创建一个名为`BasketTypes.ts`的类型的新文件，内容如下：

```jsx
import { IProduct } from "./ProductsData";

export enum BasketActionTypes {
  ADD = "BASKET/ADD"
}

export interface IBasketState {
  readonly products: IProduct[];
}

export interface IBasketAdd {
  type: BasketActionTypes.ADD;
  product: IProduct;
}

export type BasketActions = IBasketAdd;
```

+   我们的购物篮中只有一个状态，那就是购物篮中产品的数组。

+   同样也只有一个动作。这是将产品添加到购物篮中。

1.  让我们创建一个名为`BasketActions.ts`的文件，内容如下：

```jsx
import { BasketActionTypes, IBasketAdd } from "./BasketTypes";
import { IProduct } from "./ProductsData";

export const addToBasket = (product: IProduct): IBasketAdd => ({
  product,
  type: BasketActionTypes.ADD
});
```

这是用于添加到购物篮的动作创建者。该函数接受一个产品，并在具有适当动作类型的动作中返回它。

1.  现在到了减速器。让我们创建一个名为`BasketReducer.ts`的文件，其中包含以下导入语句：

```jsx
import { Reducer } from "redux";
import { BasketActions, BasketActionTypes, IBasketState } from "./BasketTypes";
```

1.  让我们为初始购物篮状态创建一个对象：

```jsx
const initialBasketState: IBasketState = {
  products: []
};
```

1.  现在让我们创建减速器：

```jsx
export const basketReducer: Reducer<IBasketState, BasketActions> = (state = initialBasketState, action) => {
  switch (action.type) {
    case BasketActionTypes.ADD: {
      return {
        ...state,
        products: state.products.concat(action.product)
      };
    }
  }
  return state || initialBasketState;
};
```

这遵循与`productsReducer`相同的模式。

一个有趣的地方要注意的是，我们如何优雅地将`product`添加到`products`数组中，而不会改变原始数组。我们使用 JavaScript 的`concat`函数，它通过将原始数组与传入的参数合并来创建一个新数组。这是在减速器中使用的一个很好的函数，其中状态变化涉及向数组添加项目。

1.  现在让我们打开`Store.ts`并导入购物篮的新减速器和状态：

```jsx
import { basketReducer } from "./BasketReducer";
import { IBasketState } from "./BasketTypes";
```

1.  让我们将购物篮状态添加到存储中：

```jsx
export interface IApplicationState {
 basket: IBasketState;
```

```jsx
  products: IProductsState;
}
```

1.  现在我们有两个减速器。因此，让我们将购物篮减速器添加到`combineReducers`函数调用中：

```jsx
export const rootReducer = combineReducers<IApplicationState>({
  basket: basketReducer,
  products: productsReducer
});
```

现在我们已经调整了我们的存储，我们可以将我们的`ProductPage`组件连接到它。

# 将 ProductPage 连接到存储

在这一部分，我们将把`ProductPage`组件连接到我们的存储中：

1.  首先将以下内容导入到`ProductPage.tsx`中：

```jsx
import { connect } from "react-redux";
import { addToBasket } from "./BasketActions";
import { getProduct } from "./ProductsActions";
import { IApplicationState } from "./Store";
```

1.  现在我们要引用存储的`getProduct`，而不是来自`ProductsData.ts`的产品。因此，让我们从此导入中删除它，使其看起来像以下内容：

```jsx
import { IProduct } from "./ProductsData";
```

1.  接下来，让我们将状态移入属性：

```jsx
interface IProps extends RouteComponentProps<{ id: string }> {
  addToBasket: typeof addToBasket;
  getProduct: typeof getProduct;
  loading: boolean;
  product?: IProduct;
  added: boolean;
}

class ProductPage extends React.Component<IProps> { ... }
```

因此，在此移动之后，应该删除`IState`接口和`Props`类型。

1.  我们可以移除构造函数，因为我们现在不需要初始化任何状态。这一切都在存储中完成。

1.  让我们将`componentDidMount`生命周期方法更改为调用获取产品的动作创建者：

```jsx
public componentDidMount() {
  if (this.props.match.params.id) {
    const id: number = parseInt(this.props.match.params.id, 10);
    this.props.getProduct(id);
  }
}
```

请注意，我们还移除了`async`关键字，因为该方法不再是异步的。

1.  继续进行`render`函数，让我们将对状态的引用替换为对属性的引用：

```jsx
public render() {
  const product = this.props.product;
  return (
    <div className="page-container">
      <Prompt when={!this.props.added} message={this.navAwayMessage}
      />
      {product || this.props.loading ? (
        <Product
          loading={this.props.loading}
          product={product}
          inBasket={this.props.added}
          onAddToBasket={this.handleAddClick}
        />
      ) : (
        <p>Product not found!</p>
      )}
    </div>
  );
}
```

1.  现在让我们来看点击处理程序，并重构它以调用添加到购物篮的动作创建者：

```jsx
private handleAddClick = () => {
  if (this.props.product) {
    this.props.addToBasket(this.props.product);
  }
};
```

1.  现在进行连接过程的最后几个步骤。让我们实现将存储中的动作创建者映射到组件属性的函数：

```jsx
const mapDispatchToProps = (dispatch: any) => {
  return {
    addToBasket: (product: IProduct) => dispatch(addToBasket(product)),
    getProduct: (id: number) => dispatch(getProduct(id))
  };
};
```

1.  将状态映射到组件 prop 有点复杂。让我们从简单的映射开始：

```jsx
const mapStateToProps = (store: IApplicationState) => {
  return {
    basketProducts: store.basket.products,
    loading: store.products.productsLoading,
    product: store.products.currentProduct || undefined
  };
};
```

请注意，我们将 null 的`currentProduct`映射到`undefined`。

1.  我们需要映射的剩余 prop 是`added`。我们需要检查商店中的当前产品是否在购物篮状态中，以设置这个`boolean`值。我们可以使用产品数组中的`some`函数来实现这一点：

```jsx
const mapStateToProps = (store: IApplicationState) => {
  return {
    added: store.basket.products.some(p => store.products.currentProduct ? p.id === store.products.currentProduct.id : false),
    ...
  };
};
```

1.  最后一步是使用 React Redux 中的`connect` HOC 将`ProductPage`组件连接到商店：

```jsx
export default connect(
  mapStateToProps,
  mapDispatchToProps
)(ProductPage);
```

现在我们可以进入运行的应用程序，访问产品页面，并将其添加到购物篮中。点击“添加到购物篮”按钮后，该按钮应该消失。如果我们浏览到另一个产品，然后回到我们已经添加到购物篮中的产品，那么“添加到购物篮”按钮就不应该出现。

所以，现在我们的产品和产品页面都连接到了 Redux 商店。在下一节中，我们将创建一个购物篮摘要组件并将其连接到商店。

# 创建并连接 BasketSummary 到商店

在本节中，我们将创建一个名为`BasketSummary`的新组件。这将显示购物篮中的物品数量，并位于我们商店的右上角。以下截图显示了购物篮摘要将在屏幕右上角的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/a46b9de9-0cd5-4ef5-aa49-42bd4cb7ebde.png)

1.  让我们创建一个名为`BasketSummary.tsx`的文件，内容如下：

```jsx
import * as React from "react";

interface IProps {
  count: number;
}

const BasketSummary: React.SFC<IProps> = props => {
  return <div className="basket-summary">{props.count}</div>;
};

export default BasketSummary;
```

这是一个简单的组件，它以一个 prop 的形式接收购物篮中产品的数量，并在一个带有`basket-summary` CSS 类的`div`中显示这个值。

1.  让我们在`index.css`中添加我们刚刚引用的 CSS 类：

```jsx
.basket-summary {
  display: inline-block;
  margin-left: 10px;
  padding: 5px 10px;
  border: white solid 2px;
}
```

1.  我们将把我们的购物篮摘要添加到我们的页眉组件中。所以，让我们把它导入到`Header.tsx`中：

```jsx
import BasketSummary from "./BasketSummary";
```

1.  让我们也从 React Redux 中导入`connect`函数：

```jsx
import { connect } from "react-redux";
```

1.  让我们也导入我们商店的状态类型：

```jsx
import { IApplicationState } from "./Store";
```

1.  为`Header`组件添加一个购物篮中产品数量的 prop：

```jsx
interface IProps extends RouteComponentProps {
 basketCount: number;
}

class Header extends React.Component<IProps, IState> { 
   public constructor(props: IProps) { ... }
   ...
}
```

我们将在这个组件中保持搜索状态为本地。

1.  现在让我们将`BasketSummary`组件添加到`Header`组件的 JSX 中：

```jsx
<header className="header">
  <div className="search-container">
    <input ... />
    <BasketSummary count={this.props.basketCount} />
  </div>
  ...
</header>
```

1.  下一步是将商店购物篮中的产品数量映射到`basketCount` prop：

```jsx
const mapStateToProps = (store: IApplicationState) => {
  return {
    basketCount: store.basket.products.length
  };
};
```

1.  最后，我们可以将`Header`组件连接到商店：

```jsx
export default connect(mapStateToProps)(withRouter(Header));
```

现在`Header`组件正在使用`BasketSummary`组件，并且也连接到商店，我们应该能够在运行的应用程序中添加产品到购物篮并看到购物篮摘要增加。

这样，这一部分关于将组件连接到商店的内容就完成了。我们已经将一些不同的组件连接到了商店，所以希望这个过程现在很清晰。

在下一节中，我们将探讨一种类似 Redux 的方法来管理组件内的状态。

# 使用 useReducer 管理状态

Redux 非常适合管理应用程序中的复杂状态。但是，如果我们要管理的状态只存在于单个组件中，那么它可能会有点重。显然，我们可以使用`setState`（对于类组件）或`useState`（对于函数组件）来管理这些情况。但是，如果状态很复杂怎么办？可能会有很多状态片段，状态交互可能涉及很多步骤，其中一些是异步的。在本节中，我们将探讨使用 React 中的`useReducer`函数来管理这些情况的方法。我们的示例将是人为的和简单的，但它将让我们了解这种方法。

我们将在我们的 React 商店的产品页面上添加一个喜欢按钮。用户可以多次喜欢一个产品。`Product`组件将跟踪喜欢的数量以及最后一次喜欢的日期和时间：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/0a921b6d-3941-43a9-b25c-d14769e8a086.png)

1.  我们将首先打开`Product.tsx`并在`Product`组件之前创建一个接口，用于我们的状态，包含喜欢的数量和最后一次喜欢的日期：

```jsx
interface ILikeState {
  likes: number;
  lastLike: Date | null;
}
```

1.  我们将创建一个变量来保存初始状态，也在`Product`之外：

```jsx
const initialLikeState: ILikeState = {
  likes: 0,
  lastLike: null
};
```

1.  现在让我们为这个动作创建一个类型：

```jsx
enum LikeActionTypes {
  LIKE = "LIKE"
}

interface ILikeAction {
  type: LikeActionTypes.LIKE;
  now: Date;
}
```

1.  我们还将创建一个包含所有动作类型的联合类型。在我们的示例中，我们只有一个动作类型，但让我们这样做以了解一个可扩展的方法：

```jsx
type LikeActions = ILikeAction;
```

1.  在`Product`组件内部，让我们在 React 中调用`useReducer`函数来获取我们的状态和`dispatch`函数：

```jsx
const [state, dispatch]: [
    ILikeState,
    (action: ILikeAction) => void
  ] = React.useReducer(reducer, initialLikeState);
```

让我们来分解一下：

+   我们传递给`useReducer`一个名为`reducer`的函数（我们还没有创建）。

+   我们还将我们的初始状态传递给`useReducer`。

+   `useReducer`返回一个包含两个元素的数组。第一个元素是当前状态，第二个是一个`dispatch`函数来调用一个动作。

1.  让我们重构这一行并解构状态，以便我们可以直接引用状态的片段：

```jsx
const [{ likes, lastLike }, dispatch]: [
    ILikeState,
    (action: ILikeAction) => void
  ] = React.useReducer(reducer, initialLikeState);
```

1.  在`Product`组件的 JSX 底部，让我们添加 JSX 来渲染我们有多少个喜欢和一个按钮来添加喜欢：

```jsx
{!props.inBasket && (
  <button onClick={handleAddClick}>Add to basket</button>
)}
<div className="like-container">
 {likes > 0 && (
 <div>{`I like this x ${likes}, last at ${lastLike}`}</div>
 )}
 <button onClick={handleLikeClick}>
 {likes > 0 ? "Like again" : "Like"}
 </button>
</div>
```

1.  让我们将刚刚引用的`like-container` CSS 类添加到`index.css`中：

```jsx
.like-container {
  margin-top: 20px;
}

.like-container button {
  margin-top: 5px;
}
```

1.  让我们也在 Like 按钮上实现点击处理程序：

```jsx
const handleLikeClick = () => {
  dispatch({ type: LikeActionTypes.LIKE, now: new Date() });
};
```

1.  我们的最后任务是在`Product`组件之外实现 reducer 函数，在`LikeActions`类型的下面：

```jsx
const reducer = (state: ILikeState = initialLikeState, action: LikeActions) => {
 switch (action.type) {
 case LikeActionTypes.LIKE:
 return { ...state, likes: state.likes + 1, lastLike: action.now };
 }
 return state;
};
```

如果我们尝试这样做，我们将在导航到产品页面后最初看到一个 Like 按钮。如果我们点击它，按钮文本会变成 Like，上面会出现一段文字，指示有多少个赞和上次点赞的时间。

这个实现感觉非常类似于在 Redux 存储中实现操作和 reducers，但这都是在一个组件内部。对于我们刚刚经历过的例子来说，这有点过度，但在我们需要管理更多状态片段的情况下可能会很有用。

# 总结

我们在本章开始时介绍了 Redux，学习了其原则和关键概念。我们了解到状态存储在一个单一对象中，并在分发 action 时通过称为 reducers 的纯函数进行更改。

我们在我们的 React 商店中创建了自己的 store 来将理论付诸实践。以下是我们在实现中学到的一些关键点：

+   为 action 类型创建枚举在引用它们时给我们提供了很好的智能感知。

+   使用接口定义 actions 可以提供很好的类型安全性，并允许我们创建一个 reducer 可以用于处理的 actions 的联合类型。

+   在状态接口中使用只读属性可以帮助我们避免直接改变状态。

+   同步 action 创建者只是简单地返回所需的 action 对象。

+   异步 action 创建者返回一个最终返回 action 对象的函数。

+   Reducer 包含了它处理的每种 action 类型的逻辑分支，通过将旧状态扩展到一个新对象中，然后用更改后的属性覆盖它来创建新状态。

+   Redux 的`createStore`函数创建了实际的 store。我们将所有的 reducer 合并在一起，还有 Redux Thunk 中间件来管理异步操作。

然后我们将一些组件连接到了 store。以下是这个过程中的关键点：

+   来自 React Redux 的`Provider`组件需要位于所有想要使用 store 的组件之上。它接收一个包含 store 的 prop。

+   然后，来自 React Redux 的`connect`高阶组件将单独的组件连接到 store。它接收两个参数，可以用于将状态和 action 创建者映射到组件 props。

在我们的 React 应用程序中实现 Redux 时，有很多要理解的细节。因为 Redux 强制我们将逻辑分解成易于理解和维护的单独部分，所以在状态管理复杂的情况下，Redux 会发挥作用。

我们学到，我们可以利用 React 的`useReducer`函数在单个组件中使用类似 Redux 的方法。当状态复杂且仅存在于单个组件中时，可以使用这种方法。

Redux 动作经常要做的一个任务是与 REST API 交互。在下一章中，我们将学习如何在基于类和基于函数的组件中与 REST API 交互。我们还将了解一个我们用来调用 REST API 的本地函数，以及一个流行的开源库。

# 问题

在结束本章之前，让我们用一些问题来测试我们的知识：

1.  action 对象中的`type`属性是必需的吗？这个属性需要被称为 type 吗？我们可以称其为其他名称吗？

1.  action 对象可以包含多少个属性？

1.  什么是 action creator？

1.  为什么我们在 React 商店应用程序中的 Redux 存储中需要 Redux Thunk？

1.  除了 Redux Thunk，我们还能用其他东西吗？

1.  在我们刚刚实现的`basketReducer`中，为什么我们不直接使用`push`函数将项目添加到购物篮状态中？也就是说，高亮显示的行有什么问题？

```jsx
export const basketReducer: Reducer<IBasketState, BasketActions> = (
  state = initialBasketState,
  action
) => {
  switch (action.type) {
    case BasketActionTypes.ADD: {
      state.products.push(action.product);
    }
  }
  return state || initialBasketState;
};
```

# 进一步阅读

以下链接是关于 React Redux 的更多信息的好资源：

+   Redux 在线文档非常值得阅读，网址是[`redux.js.org`](https://redux.js.org)。

+   除了这些核心 Redux 文档外，React Redux 文档也值得一看。这些文档位于[`react-redux.js.org/`](https://react-redux.js.org/)。

+   Redux Thunk GitHub 位于[`github.com/reduxjs/redux-thunk`](https://github.com/reduxjs/redux-thunk)。主页包含一些有用的信息和示例。


# 第九章：与 RESTful API 交互

与 RESTful API 交互是构建应用程序时我们需要做的非常常见的任务，它总是导致我们必须编写异步代码。因此，在本章的开始，我们将详细了解一般的异步代码。

有许多库可以帮助我们与 REST API 交互。在本章中，我们将看看原生浏览器函数和一个流行的开源库来与 REST API 交互。我们将发现开源库相对于原生函数的额外功能。我们还将看看如何在 React 类和基于函数的组件中与 REST API 交互。

在本章中，我们将学习以下主题：

+   编写异步代码

+   使用 fetch

+   使用 axios 与类组件

+   使用 axios 与函数组件

# 技术要求

在本章中，我们使用以下技术：

+   **TypeScript playground**：这是一个网站，位于[`www.typescriptlang.org/play/`](https://www.typescriptlang.org/play/)，允许我们在不安装任何东西的情况下玩耍异步代码。

+   **Node.js 和** `npm`：TypeScript 和 React 依赖于这些。我们可以从[`nodejs.org/en/download/`](https://nodejs.org/en/download/)安装这些。如果我们已经安装了这些，请确保`npm`至少是 5.2 版本。

+   **TypeScript**：可以通过终端中的以下命令使用`npm`安装：

```jsx
npm install -g typescript
```

+   **Visual Studio Code**。我们需要一个编辑器来编写我们的 React 和 TypeScript 代码，可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)安装。我们还需要在 Visual Studio Code 中安装 TSLint (by egamma) 和 Prettier (by Estben Petersen) 扩展。

+   `jsonplaceholder.typicode.com`：我们将使用这个在线服务来帮助我们学习如何与 RESTful API 交互。

本章中的所有代码片段都可以在[`github.com/carlrip/LearnReact17WithTypeScript/tree/master/09-RestfulAPIs.`](https://github.com/carlrip/LearnReact17WithTypeScript/tree/master/09-RestfulAPIs)上找到

# 编写异步代码

TypeScript 代码默认是同步执行的，每行代码都会依次执行。然而，TypeScript 代码也可以是异步的，这意味着事情可以独立于我们的代码发生。调用 REST API 就是异步代码的一个例子，因为 API 请求是在我们的 TypeScript 代码之外处理的。因此，与 REST API 交互会迫使我们编写异步代码。

在本节中，我们将花时间了解在编写异步代码时可以采取的方法，然后再使用它们与 RESTful API 进行交互。我们将在下一节开始时看一下回调函数。

# 回调函数

回调是我们将作为参数传递给异步函数的函数，在异步函数完成时调用。在下一节中，我们将通过一个使用回调的异步代码示例进行说明。

# 回调执行

让我们在 TypeScript 播放器中通过一个使用回调的异步代码示例来进行说明。让我们输入以下代码：

```jsx
let firstName: string;
setTimeout(() => {
  firstName = "Fred";
  console.log("firstName in callback", firstName);
}, 1000);
console.log("firstName after setTimeout", firstName); 
```

该代码调用了 JavaScript 的`setTimeout`函数，这是一个异步函数。它以回调作为第一个参数，并以执行应等待的毫秒数作为第二个参数。

我们使用箭头函数作为回调函数，在其中将`firstName`变量设置为"Fred"并将其输出到控制台。我们还在调用`setTimeout`后立即在控制台中记录`firstName`。

那么，哪个`console.log`语句会首先执行呢？如果我们运行代码并查看控制台，我们会看到最后一行首先执行：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/b9a54558-5be3-47a1-8921-2cd69f4933e2.png)

关键点在于，在调用`setTimeout`之后，执行会继续到下一行代码。执行不会等待回调被调用。这可能会使包含回调的代码比同步代码更难阅读，特别是当我们在回调中嵌套回调时。许多开发人员称之为**回调地狱**！

那么，我们如何处理异步回调代码中的错误？我们将在下一节中找出答案。

# 处理回调错误

在本节中，我们将探讨在使用回调代码时如何处理错误：

1.  让我们从在 TypeScript 播放器中输入以下代码开始：

```jsx
try {
 setTimeout(() => {
 throw new Error("Something went wrong");
 }, 1000);
} catch (ex) {
 console.log("An error has occurred", ex); 
}
```

我们再次使用`setTimeout`来尝试回调。这次，在回调函数内抛出一个错误。我们希望使用`try / catch`来捕获回调外部的错误，围绕`setTimeout`函数。

如果我们运行代码，我们会发现我们没有捕获错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/08ffe4f4-0b57-4cc6-8d4b-ed7d664004bf.png)

1.  我们必须在回调函数内处理错误。因此，让我们将我们的示例调整为以下内容：

```jsx
interface IResult {
  success: boolean;
  error?: any;
}
let result: IResult = { success: true };
setTimeout(() => {
  try {
    throw new Error("Something went wrong");
  } catch (ex) {
    result.success = false;
    result.error = ex;
  }
}, 1000);
console.log(result);
```

这次，`try / catch`在回调函数内。我们使用一个变量`result`来确定回调是否成功执行，以及任何错误。`IResult`接口为我们提供了对结果`变量`的良好类型安全性。

如果我们运行这段代码，我们将看到我们成功处理了错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/ec166585-af59-4cc9-b805-2cb395749311.png)

因此，处理错误以及读取基于回调的代码是一个挑战。幸运的是，有替代方法来处理这些挑战，我们将在接下来的部分中介绍。

# 承诺

promise 是一个 JavaScript 对象，它代表异步操作的最终完成（或失败）及其结果值。接下来，我们将看一个消耗基于 promise 的函数的示例，然后创建我们自己的基于 promise 的函数。

# 消耗基于 promise 的函数

让我们快速看一下一些暴露了基于 promise 的 API 的代码：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts")
  .then(response => response.json()) 
  .then(data => console.log(data))
  .catch(json => console.log("error", json));
```

+   这个函数是用于与 RESTful API 交互的本机 JavaScript `fetch`函数

+   该函数接受一个用于请求的 URL。

+   它有一个`then`方法来处理响应和读取响应主体

+   它有一个`catch`方法来处理任何错误

代码执行流程与我们阅读的方式相同。我们还不必在`then`方法中做任何额外的工作来处理错误。因此，这比使用基于回调的异步代码要好得多。

在下一节中，我们将创建我们自己的基于 promise 的函数。

# 创建一个基于 promise 的函数

在本节中，我们将创建一个`wait`函数，以异步等待传递的毫秒数：

1.  让我们在 TypeScript playground 中输入以下内容：

```jsx
const wait = (ms: number) => {
  return new Promise((resolve, reject) => {
    if (ms > 1000) {
      reject("Too long");
    }
    setTimeout(() => {
      resolve("Sucessfully waited");
    }, ms);
  });
};
```

+   该函数开始通过返回一个`Promise`对象，该对象将需要异步执行的函数作为其构造函数参数

+   `promise`函数接受一个`resolve`参数，这是一个在函数执行完成时调用的函数

+   promise 函数还接受一个`reject`参数，这是一个在函数出错时调用的函数

+   在内部，我们使用带有回调的`setTimeout`来进行实际的等待

1.  让我们消费我们基于 promise 的`wait`函数：

```jsx
wait(500)
 .then(result => console.log("then >", result))
 .catch(error => console.log("catch >", error));
```

该函数只是在等待 500 毫秒后将结果或错误输出到控制台。

因此，让我们尝试运行它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/43ce9513-e1b1-4b0a-b4c4-b9f14206adf1.png)

正如我们所看到的，控制台中的输出表明`then`方法被执行了。

1.  如果我们用大于 1000 的参数调用`wait`函数，`catch`方法应该被调用。让我们试一试：

```jsx
wait(1500)
 .then(result => console.log("then >", result))
 .catch(error => console.log("catch >", error));
```

如预期的那样，`catch`方法被执行：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5c3b5730-c747-4e17-9499-23f7a4c9461f.png)

因此，promise 给了我们一种很好的编写异步代码的方式。然而，在本书的早期我们已经使用了另一种方法。我们将在下一节中介绍这种方法。

# 异步和等待

`async`和`await`是两个 JavaScript 关键字，我们可以使用它们使异步代码的阅读几乎与同步代码相同：

1.  让我们看一个例子，消费我们在上一节中创建的`wait`函数，将以下代码输入到 TypeScript playground 中，放在`wait`函数声明之后：

```jsx
const someWork = async () => {
  try {
    const result = await wait(500); 
    console.log(result);
  } catch (ex) {
    console.log(ex);
  }
};

someWork();
```

+   我们创建了一个名为`someWork`的箭头函数，并用`async`关键字标记为异步。

+   然后我们调用带有`await`关键字前缀的`wait`。这会暂停下一行的执行，直到`wait`完成。

+   `try / catch`将捕获任何错误。

因此，代码非常类似于您在同步方式下编写的方式。

如果我们运行这个例子，我们会得到确认，`try`分支中的`console.log`语句等待`wait`函数完全完成后才执行：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/0278f6b8-7431-4059-8cec-87efa7941022.png)

1.  让我们将等待时间改为`1500`毫秒：

```jsx
const result = await wait(1500); 
```

如果我们运行这个，我们会看到一个错误被引发并捕获：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/5af59f14-a6b6-44c0-bbe9-d6701cde368d.png)

因此，`async`和`await`使我们的代码易于阅读。在 TypeScript 中使用这些的一个好处是，代码可以被转译以在旧版浏览器中运行。例如，我们可以使用`async`和`await`编码，同时支持 IE。

现在我们对编写异步代码有了很好的理解，我们将在接下来的章节中将其付诸实践，当我们与 RESTful API 交互时。

# 使用 fetch

`fetch`函数是一个原生的 JavaScript 函数，我们可以用它来与 RESTful API 交互。在本节中，我们将通过`fetch`进行一些常见的 RESTful API 交互，从获取数据开始。在本节中，我们将与出色的`JSONPlaceholder` REST API 进行交互。

# 使用 fetch 获取数据

在本节中，我们将使用`fetch`从`JSONPlaceholder` REST API 获取一些帖子，从基本的`GET`请求开始。

# 基本的 GET 请求

让我们打开 TypeScript playground 并输入以下内容：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts")
  .then(response => response.json())
  .then(data => console.log(data));
```

以下是一些关键点：

+   `fetch`函数中的第一个参数是请求的 URL

+   `fetch`是一个基于承诺的函数

+   第一个`then`方法处理响应

+   第二个`then`方法处理当响应体已解析为 JSON 时

如果我们运行代码，应该会在控制台输出一个帖子数组：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/be4bbc0d-04b2-4867-98f1-1ea1c4f9d7e6.png)

# 获取响应状态

我们经常需要检查请求的状态。我们可以这样做：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts").then(response => {
  console.log(response.status, response.ok); 
});
```

+   响应的`status`属性给出了响应的 HTTP 状态码

+   响应的`ok`属性是一个`boolean`，返回 HTTP 状态码是否在 200 范围内

如果我们运行先前的代码，我们会在控制台得到 200 和 true 的输出。

让我们尝试一个帖子不存在的示例请求：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/1001").then(response => {
  console.log(response.status, response.ok); 
});
```

如果我们运行上述代码，我们会在控制台得到 404 和 false 的输出。

# 处理错误

使用基于承诺的函数，我们在`catch`方法中处理错误：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts")
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(json => console.log("error", json));
```

然而，`catch`方法不会捕获不在 200 范围内的响应。在先前的示例中，我们得到了响应状态码为 404。因此，HTTP 错误状态码可以在第一个`then`方法中处理，而不是`catch`方法。

那么，`catch`方法是用来做什么的？答案是捕获网络错误。

这就是使用`fetch`获取数据的方法。在下一节中，我们将介绍发布数据。

# 使用 fetch 创建数据

在本节中，我们将使用`fetch`来使用`JSONPlaceholder` REST API 创建一些数据。

# 基本的 POST 请求

通过 REST API 创建数据通常涉及使用 HTTP `POST`方法，并将要创建的数据放在请求体中。

让我们打开 TypeScript playground 并输入以下内容：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts", {
  method: "POST",
  body: JSON.stringify({
    title: "Interesting post",
    body: "This is an interesting post about ...",
    userId: 1
  })
})
  .then(response => {
    console.log(response.status); 
    return response.json();
  })
  .then(data => console.log(data));
```

`fetch`调用与获取数据的方式基本相同。关键区别在于第二个参数，它是一个包含请求的方法和主体的选项对象。还要注意主体需要是一个`string`。

如果我们运行上述代码，我们将在控制台中得到 201 和包含生成的帖子 ID 的对象。

# 请求 HTTP 标头

我们经常需要在请求中包含 HTTP 标头。我们可以在`options`对象中的`headers`属性中指定这些内容：

```jsx

fetch("https://jsonplaceholder.typicode.com/posts", {
 method: "POST",
 headers: {
 "Content-Type": "application/json",
 Authorization: "bearer some-bearer-token"
 },
  body: JSON.stringify({
    title: "Interesting post",
    body: "This is an interesting post about ...",
    userId: 1
  })
})
  .then(response => {
    console.log(response.status); 
    return response.json();
  })
  .then(data => console.log(data));

```

请求标头可以用于任何 HTTP 方法，而不仅仅是 HTTP `POST`。例如，我们可以用于`GET`请求如下：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/1", {
  headers: {
 "Content-Type": "application/json",
 Authorization: "bearer some-bearer-token"
 }
}).then(...);
```

因此，这就是如何使用`fetch`向 REST API 发布数据。在下一节中，我们将看看如何更改数据。

# 使用 fetch 更改数据

在本节中，我们将使用`fetch`通过 REST API 更改一些数据。

# 基本的 PUT 请求

通过`PUT`请求通常更改数据。让我们打开 TypeScript 播放器并输入以下内容：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/1", {
  method: "PUT",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    title: "Corrected post",
    body: "This is corrected post about ...",
    userId: 1
  })
})
  .then(response => {
    console.log(response.status);
    return response.json();
  })
  .then(data => console.log(data)); 
```

因此，进行 HTTP `PUT`的`fetch`调用的结构与`POST`请求非常相似。唯一的区别是我们在选项对象中指定`method`属性为`PUT`。

如果我们运行上述代码，我们将得到 200 和更新的`POST`对象输出到控制台。

# 基本的 PATCH 请求

一些 REST API 提供`PATCH`请求，允许我们提交对资源部分的更改。让我们打开 TypeScript 播放器并输入以下内容：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/1", {
  method: "PATCH",
  headers: {
    "Content-type": "application/json"
  },
  body: JSON.stringify({
    title: "Corrected post"
  })
})
 .then(response => {
    console.log(response.status); 
    return response.json();
  })
  .then(data => console.log(data));
```

因此，我们正在使用`PATCH` HTTP 方法提交对帖子标题的更改。如果我们运行上述代码，我们将得到 200 和更新的帖子对象输出到控制台。

因此，这就是如何使用`fetch`进行`PUT`和`PATCH`。在下一节中，我们将删除一些数据。

# 使用 fetch 删除数据

通常，我们通过 REST API 上的`DELETE` HTTP 方法删除数据。在 TypeScript 播放器中输入以下内容：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/1", {
  method: "DELETE"
}).then(response => {
  console.log(response.status); 
});
```

因此，我们正在请求使用`DELETE`方法删除帖子。

如果我们运行上述代码，我们将在控制台中得到 200 的输出。

因此，我们已经学会了如何使用原生的`fetch`函数与 RESTful API 进行交互。在下一节中，我们将看看如何使用流行的开源库执行相同操作，并了解其相对于`fetch`的优势。

# 使用 axios 与类组件

`axios`是一个流行的开源 JavaScript HTTP 客户端。我们将构建一个小型的 React 应用程序，从`JSONPlaceholder` REST API 中创建、读取、更新和删除帖子。在此过程中，我们将发现`axios`相对于`fetch`的一些优点。在下一节中，我们的第一个任务是安装`axios`。

# 安装 axios

在我们安装`axios`之前，我们将快速创建我们的小型 React 应用程序：

1.  在我们选择的文件夹中，让我们打开 Visual Studio Code 和它的终端，并输入以下命令来创建一个新的 React 和 TypeScript 项目：

```jsx
npx create-react-app crud-api --typescript
```

请注意，我们使用的 React 版本至少需要是`16.7.0-alpha.0`版本。我们可以在`package.json`文件中检查这一点。如果`package.json`中的 React 版本旧于`16.7.0-alpha.0`，那么我们可以使用以下命令安装这个版本：

```jsx
npm install react@16.7.0-alpha.0
npm install react-dom@16.7.0-alpha.0
```

1.  项目创建后，让我们将 TSLint 作为开发依赖项添加到我们的项目中，以及一些与 React 和 Prettier 配合良好的规则：

```jsx
cd crud-api
npm install tslint tslint-react tslint-config-prettier --save-dev
```

1.  现在让我们添加一个包含一些规则的`tslint.json`文件：

```jsx
{
  "extends": ["tslint:recommended", "tslint-react", "tslint-config-prettier"],
  "rules": {
    "ordered-imports": false,
    "object-literal-sort-keys": false,
    "jsx-no-lambda": false,
    "no-debugger": false,
    "no-console": false,
  },
  "linterOptions": {
    "exclude": [
      "config/**/*.js",
      "node_modules/**/*.ts",
      "coverage/lcov-report/*.js"
    ]
  }
}
```

1.  如果我们打开`App.tsx`，会有一个 linting 错误。所以，让我们通过在`render`方法上添加`public`修饰符来解决这个问题：

```jsx
class App extends Component {
  public render() {
    return ( ... );
  }
}
```

1.  现在我们可以使用 NPM 安装`axios`：

```jsx
npm install axios
```

请注意，`axios`中包含 TypeScript 类型，因此我们不需要安装它们。

1.  在继续开发之前，让我们先运行我们的应用程序：

```jsx
npm start
```

应用程序将在浏览器中启动并运行。在下一节中，我们将使用 axios 从 JSONPlaceholder 获取帖子。

# 使用 axios 获取数据

在本节中，我们将在`App`组件中呈现来自`JSONPlaceholder`的帖子。

# 基本的 GET 请求

我们将从`axios`开始，使用基本的 GET 请求获取帖子，然后在无序列表中呈现它们：

1.  让我们打开`App.tsx`并为`axios`添加一个导入语句：

```jsx
import axios from "axios";
```

1.  让我们还为从 JSONPlaceholder 获取的帖子创建一个接口：

```jsx
interface IPost {
  userId: number;
  id?: number;
  title: string;
  body: string;
}
```

1.  我们将把帖子存储在状态中，所以让我们为此添加一个接口：

```jsx
interface IState {
 posts: IPost[];
}
class App extends React.Component<{}, IState> { ... }
```

1.  然后在构造函数中将帖子状态初始化为空数组：

```jsx
class App extends React.Component<{}, IState> {
  public constructor(props: {}) {
 super(props);
 this.state = {
 posts: []
 };
 }
}
```

1.  从 REST API 获取数据时，通常会在`componentDidMount`生命周期方法中进行。所以，让我们使用`axios`来获取我们的帖子：

```jsx
public componentDidMount() {
  axios
    .get<IPost[]>("https://jsonplaceholder.typicode.com/posts")
    .then(response => {
      this.setState({ posts: response.data });
    });
}
```

+   我们使用`axios`中的`get`函数来获取数据，这是一个类似于`fetch`的基于 Promise 的函数

+   这是一个通用函数，它接受响应主体类型作为参数

+   我们将我们请求的 URL 作为参数传递给`get`函数

+   然后我们可以在`then`方法中处理响应

+   我们通过响应对象中的`data`属性获得对响应主体的访问权限，该对象是根据通用参数进行了类型化。

因此，这比`fetch`更好的两种方式：

+   我们可以轻松输入响应

+   有一步（而不是两步）来获取响应主体

1.  既然我们已经在组件状态中有了帖子，让我们在`render`方法中呈现帖子。让我们还删除`header`标签：

```jsx
public render() {
  return (
    <div className="App">
      <ul className="posts">
 {this.state.posts.map(post => (
 <li key={post.id}>
 <h3>{post.title}</h3>
 <p>{post.body}</p>
 </li>
 ))}
 </ul>
    </div>
  );
}
```

我们使用`posts`数组的`map`函数来显示帖子的无序列表。

1.  我们引用了一个`posts` CSS 类，因此让我们将其添加到`index.css`中：

```jsx
.posts {
  list-style: none;
  margin: 0px auto;
  width: 800px;
  text-align: left;
}
```

如果我们查看正在运行的应用程序，它现在将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-react-ts3/img/c8ae59fc-f745-47d3-aca5-ce24e4911e01.png)

因此，使用`axios`进行基本的`GET`请求非常简单。我们需要在类组件中使用`componentDidMount`生命周期方法，以便进行 REST API 调用，该调用将从响应中呈现数据。

但是我们如何处理错误呢？我们将在下一节中介绍这一点。

# 处理错误

1.  让我们调整我们的请求中的 URL：

```jsx
.get<IPost[]>("https://jsonplaceholder.typicode.com/postsX")
```

如果我们查看正在运行的应用程序，帖子将不再被呈现。

1.  我们希望处理这种情况并给用户一些反馈。我们可以使用`catch`方法来做到这一点：

```jsx
axios
  .get<IPost[]>("https://jsonplaceholder.typicode.com/postsX")
  .then( ... )
  .catch(ex => {
 const error =
 ex.response.status === 404
 ? "Resource not found"
 : "An unexpected error has occurred";
 this.setState({ error });
 });
```

因此，与`fetch`不同，HTTP 状态错误代码可以在`catch`方法中处理。`catch`中的错误对象参数包含一个包含有关响应的信息的`response`属性，包括 HTTP 状态代码。

1.  我们在`catch`方法中引用了一个名为`error`的状态片段。我们将在下一步中使用它来呈现错误消息。但是，我们首先需要将此状态添加到我们的接口并进行初始化：

```jsx
interface IState {
 posts: IPost[];
  error: string;
}
class App extends React.Component<{}, IState> {
  public constructor(props: {}) {
    super(props);
    this.state = {
      posts: [],
      error: "" 
    };
  }
}
```

1.  然后，如果包含值，让我们呈现错误：

```jsx
<ul className="posts">
  ...
</ul>
{this.state.error && <p className="error">{this.state.error}</p>}
```

1.  让我们现在将刚刚引用的`error` CSS 类添加到`index.css`中：

```jsx
.error {
  color: red;
}
```

如果我们现在查看正在运行的应用程序，我们将看到红色的资源未找到。

1.  现在让我们将 URL 更改为有效的 URL，以便我们可以继续查看如何在下一节中包含 HTTP 标头：

```jsx
.get<IPost[]>("https://jsonplaceholder.typicode.com/posts")
```

因此，使用`axios`处理 HTTP 错误与使用`fetch`不同。我们在`fetch`的第一个`then`方法中处理它们，而我们在`axios`的`catch`方法中处理它们。

# 请求 HTTP 标头

为了在请求中包含 HTTP 标头，我们需要向`get`函数添加第二个参数，该参数可以包含各种选项，包括 HTTP 标头。

让我们在我们的请求中添加一个内容类型的 HTTP 标头：

```jsx
.get<IPost[]>("https://jsonplaceholder.typicode.com/posts", {
  headers: {
 "Content-Type": "application/json"
 }
})
```

因此，我们在一个名为`headers`的属性中的对象中定义了 HTTP 标头。

如果我们查看正在运行的应用程序，它将完全相同。JSONPlaceholder REST API 不需要内容类型，但我们与之交互的其他 REST API 可能需要。

在下一节中，我们将看看在`fetch`函数中很难实现的一些东西，即在请求上指定超时的能力。

# 超时

在一定时间后超时请求可以改善我们应用的用户体验：

1.  让我们给我们的请求添加一个超时：

```jsx
.get<IPost[]>("https://jsonplaceholder.typicode.com/posts", {
  headers: {
    "Content-Type": "application/json"
  },
  timeout: 1
})
```

因此，向`axios`请求添加超时非常简单。我们只需在选项对象中添加一个`timeout`属性，并设置适当的毫秒数。我们已经指定了 1 毫秒，这样我们就可以希望看到请求超时。

1.  现在让我们在`catch`方法中处理超时：

```jsx
.catch(ex => {
  const error =
    ex.code === "ECONNABORTED"
 ? "A timeout has occurred"
      : ex.response.status === 404
        ? "Resource not found"
        : "An unexpected error has occurred";
  this.setState({ error });
});
```

因此，我们在捕获的错误对象中检查`code`属性，以确定是否发生了超时。

如果我们查看正在运行的应用程序，我们应该得到确认，即已发生超时，并显示为红色的超时已发生。

1.  现在让我们将超时时间更改为更合理的值，这样我们就可以继续看看如何在下一节中允许用户取消请求：

```jsx
.get<IPost[]>("https://jsonplaceholder.typicode.com/posts", {
  ...
  timeout: 5000
})
```

# 取消请求

允许用户取消请求可以改善我们应用的用户体验。在本节中，我们将借助`axios`来实现这一点：

1.  首先，我们将从`axios`中导入`CancelTokenSource`类型：

```jsx
import axios, { CancelTokenSource } from "axios";
```

1.  让我们在状态中添加一个取消令牌和一个加载标志：

```jsx
interface IState {
 posts: IPost[];
 error: string;
 cancelTokenSource?: CancelTokenSource;
 loading: boolean;
}
```

1.  让我们在构造函数中初始化加载状态：

```jsx
this.state = {
  posts: [],
  error: "",
  loading: true
};
```

我们已将取消令牌定义为可选的，因此我们不需要在构造函数中初始化它。

1.  接下来，我们将生成取消令牌源并将其添加到状态中，就在我们进行`GET`请求之前：

```jsx
public componentDidMount() {
  const cancelToken = axios.CancelToken;
 const cancelTokenSource = cancelToken.source();
 this.setState({ cancelTokenSource });
  axios
    .get<IPost[]>(...)
    .then(...)
    .catch(...);
}
```

1.  然后我们可以在 GET 请求中使用令牌：

```jsx
.get<IPost[]>("https://jsonplaceholder.typicode.com/posts", {
  cancelToken: cancelTokenSource.token,
  ...
})
```

1.  我们可以按照以下方式在`catch`方法中处理取消。让我们还将`loading`状态设置为`false`：

```jsx
.catch(ex => {
  const error = axios.isCancel(ex)
 ? "Request cancelled"
    : ex.code === "ECONNABORTED"
      ? "A timeout has occurred"
      : ex.response.status === 404
        ? "Resource not found"
        : "An unexpected error has occurred";
  this.setState({ error, loading: false });
});
```

因此，我们使用`axios`中的`isCancel`函数来检查请求是否已被取消。

1.  当我们在`componentDidMount`方法中时，让我们在`then`方法中将`loading`状态设置为`false`：

```jsx
.then(response => {
  this.setState({ posts: response.data, loading: false });
})
```

1.  在`render`方法中，让我们添加一个取消按钮，允许用户取消请求：

```jsx
{this.state.loading && (
 <button onClick={this.handleCancelClick}>Cancel</button>
)}
<ul className="posts">...</ul>
```

1.  让我们实现刚刚引用的取消按钮处理程序：

```jsx
private handleCancelClick = () => {
  if (this.state.cancelTokenSource) {
    this.state.cancelTokenSource.cancel("User cancelled operation");
  }
};
```

为了取消请求，在取消令牌源上调用取消方法。

所以，用户现在可以通过点击取消按钮来取消请求。

1.  现在，这将很难测试，因为我们正在使用的 REST API 非常快！因此，为了看到一个被取消的请求，让我们在`componentDidMount`方法中在请求发送后立即取消它：

```jsx
axios
  .get<IPost[]>( ... )
  .then(response => { ... })
  .catch(ex => { ... });

cancelTokenSource.cancel("User cancelled operation");
```

如果我们查看正在运行的应用程序，我们应该看到请求被取消的验证，显示为红色的“请求已取消”。

因此，`axios`使得通过添加取消请求的能力来改善我们应用的用户体验变得非常容易。

在我们继续下一节之前，我们将使用`axios`来创建数据，让我们删除刚刚添加的行，以便在请求后立即取消它。

# 使用 axios 创建数据

现在让我们继续创建数据。我们将允许用户输入帖子标题和正文并保存：

1.  让我们首先为标题和正文创建一个新的状态：

```jsx
interface IState {
  ...
  editPost: IPost;
}
```

1.  让我们也初始化这个新状态：

```jsx
public constructor(props: {}) {
  super(props);
  this.state = {
    ...,
    editPost: {
      body: "",
      title: "",
 userId: 1
 }
  };
}
```

1.  我们将创建一个`input`和`textarea`来从用户那里获取帖子的标题和正文：

```jsx
<div className="App">
  <div className="post-edit">
 <input
 type="text"
 placeholder="Enter title"
 value={this.state.editPost.title}
 onChange={this.handleTitleChange}
 />
 <textarea
 placeholder="Enter body"
 value={this.state.editPost.body}
 onChange={this.handleBodyChange}
 />
 <button onClick={this.handleSaveClick}>Save</button>
 </div>
  {this.state.loading && (
    <button onClick={this.handleCancelClick}>Cancel</button>
  )}
  ...
</div>
```

1.  让我们实现刚刚引用的更改处理程序来更新状态：

```jsx
private handleTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  this.setState({
    editPost: { ...this.state.editPost, title: e.currentTarget.value }
  });
};

private handleBodyChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
  this.setState({
    editPost: { ...this.state.editPost, body: e.currentTarget.value }
  });
};
```

1.  我们可以在`index.css`中添加一些 CSS 来使这一切看起来合理：

```jsx
.post-edit {
  display: flex;
  flex-direction: column;
  width: 300px;
  margin: 0px auto;
}
.post-edit input {
  font-family: inherit;
  width: 100%;
  margin-bottom: 5px;
}

.post-edit textarea {
  font-family: inherit;
  width: 100%;
  margin-bottom: 5px;
}

.post-edit button {
  font-family: inherit;
  width: 100px;
}
```

1.  我们还可以开始处理保存点击处理程序，并使用`axios`将新帖子`POST`到 REST API：

```jsx
private handleSaveClick = () => {
  axios
    .post<IPost>(
      "https://jsonplaceholder.typicode.com/posts",
      {
        body: this.state.editPost.body,
        title: this.state.editPost.title,
        userId: this.state.editPost.userId
      },
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    )
};
```

1.  我们可以使用`then`方法处理响应：

```jsx
.then(response => {
  this.setState({
    posts: this.state.posts.concat(response.data)
  });
});
```

因此，我们将新的帖子与现有帖子连接起来，为状态创建一个新的帖子数组。

`post`函数调用的结构与`get`非常相似。实际上，我们可以像对`get`一样添加错误处理、超时和取消请求的能力。

如果我们在运行的应用程序中添加一个新帖子并单击“保存”按钮，我们会看到它添加到帖子列表的底部。

接下来，我们将允许用户更新帖子。

# 使用 axios 更新数据

现在让我们继续更新数据。我们将允许用户点击现有帖子中的“更新”按钮来更改和保存它：

1.  让我们首先在帖子列表中的每个列表项中创建一个“更新”按钮：

```jsx
<li key={post.id}>
  <h3>{post.title}</h3>
  <p>{post.body}</p>
  <button onClick={() => this.handleUpdateClick(post)}>
 Update
 </button>
</li>
```

1.  我们现在可以实现“更新”按钮的点击处理程序，该处理程序将在组件状态中设置正在编辑的帖子：

```jsx
private handleUpdateClick = (post: IPost) => {
  this.setState({
    editPost: post
  });
};
```

1.  在我们现有的保存点击处理程序中，我们现在需要为现有的`POST`请求和我们需要实现的`PUT`请求编写两个代码分支：

```jsx
private handleSaveClick = () => {
  if (this.state.editPost.id) {
    // TODO - make a PUT request
  } else {
    axios
      .post<IPost>( ... )
      .then( ... );
  }
};
```

1.  现在让我们实现`PUT`请求：

```jsx
if (this.state.editPost.id) {
  axios
 .put<IPost>(
 `https://jsonplaceholder.typicode.com/posts/${
 this.state.editPost.id
 }`,
 this.state.editPost,
 {
 headers: {
 "Content-Type": "application/json"
 }
 }
 )
 .then(() => {
 this.setState({
 editPost: {
 body: "",
 title: "",
 userId: 1
 },
 posts: this.state.posts
 .filter(post => post.id !== this.state.editPost.id)
 .concat(this.state.editPost)
 });
 });
} else {
  ...
}
```

因此，我们过滤并连接更新的帖子，为状态创建一个新的帖子数组。

`put`函数调用的结构与`get`和`post`非常相似。同样，我们可以添加错误处理、超时和取消请求的能力，就像我们为`get`做的那样。

在运行的应用程序中，如果我们点击帖子中的“更新”按钮，更改标题和正文，然后点击“保存”按钮，我们会看到它从原来的位置移除，并以新的标题和正文添加到帖子列表的底部。

如果我们想要`PATCH`一个帖子，我们可以使用`patch` `axios`方法。这与`put`的结构相同，但是我们可以只传递需要更新的值，而不是传递整个被更改的对象。

在下一节中，我们将允许用户删除帖子。

# 使用 axios 删除数据

现在让我们继续删除数据。我们将允许用户点击现有帖子中的“删除”按钮来删除它：

1.  让我们首先在帖子的每个列表项中创建一个“删除”按钮：

```jsx
<li key={post.id}>
  <h3>{post.title}</h3>
  <p>{post.body}</p>
  <button onClick={() => this.handleUpdateClick(post)}>
    Update
  </button>
  <button onClick={() => this.handleDeleteClick(post)}>
 Delete
 </button>
</li>
```

1.  现在我们可以创建删除按钮的点击处理程序：

```jsx
private handleDeleteClick = (post: IPost) => {
  axios
    .delete(`https://jsonplaceholder.typicode.com/posts/${post.id}`)
    .then(() => {
      this.setState({
        posts: this.state.posts.filter(p => p.id !== post.id)
      });
    });
};
```

因此，我们使用`axios`的`delete`方法来发出 HTTP 的`DELETE`请求，其结构与其他方法相同。

如果我们进入运行的应用程序，我们应该在每个帖子中看到一个删除按钮。如果我们点击其中一个按钮，我们会在短暂的延迟后看到它从列表中移除。

因此，这就结束了关于使用类组件的`axios`的部分。我们已经看到，`axios`函数比`fetch`更清晰，而且具有诸如有类型的响应、超时和请求取消等功能，使其成为许多开发人员的首选。在下一节中，我们将重构刚刚实现的`App`组件为函数组件。

# 在函数组件中使用 axios

在本节中，我们将在函数组件中使用`axios`实现 REST API 调用。我们将重构上一节中构建的`App`组件：

1.  首先，我们将声明一个名为`defaultPosts`的常量，它将保存稍后将使用的默认帖子状态。我们将在`IPost`接口之后添加这个常量，并将其设置为空数组：

```jsx
const defaultPosts: IPost[] = [];
```

1.  我们将删除`IState`接口，因为状态现在将被构造为各个状态片段。

1.  我们还将删除之前的`App`类组件。

1.  接下来，让我们在`defaultPosts`常量下开始`App`函数组件：

```jsx
const App: React.SFC = () => {}
```

1.  现在我们可以为帖子、错误、取消令牌、加载标志和正在编辑的帖子创建状态：

```jsx
const App: React.SFC = () => {
  const [posts, setPosts]: [IPost[], (posts: IPost[]) => void] = React.useState(defaultPosts);

  const [error, setError]: [string, (error: string) => void] = React.useState("");

  const cancelToken = axios.CancelToken;
  const [cancelTokenSource, setCancelTokenSource]: [CancelTokenSource,(cancelSourceToken: CancelTokenSource) => void] = React.useState(cancelToken.source());

  const [loading, setLoading]: [boolean, (loading: boolean) => void] = React.useState(false);

  const [editPost, setEditPost]: [IPost, (post: IPost) => void] = React.useState({
    body: "",
    title: "",
    userId: 1
  });
}
```

因此，我们使用`useState`函数来定义和初始化所有这些状态片段。

1.  当组件首次挂载时，我们希望进行 REST API 调用以获取帖子。在状态定义的行之后，我们可以使用`useEffect`函数，将空数组作为第二个参数进行这样的操作：

```jsx
React.useEffect(() => {
  // TODO - get posts
}, []);
```

1.  让我们在箭头函数中调用 REST API 以获取帖子：

```jsx
React.useEffect(() => {
  axios
 .get<IPost[]>("https://jsonplaceholder.typicode.com/posts", {
 cancelToken: cancelTokenSource.token,
 headers: {
 "Content-Type": "application/json"
 },
 timeout: 5000
 });
}, []);
```

1.  让我们处理响应并设置帖子状态，同时将加载状态设置为`false`：

```jsx
React.useEffect(() => {
  axios
    .get<IPost[]>(...)
    .then(response => {
 setPosts(response.data);      setLoading(false);
 });
}, []);
```

1.  让我们也处理任何错误，将错误状态与加载状态设置为`false`：

```jsx
React.useEffect(() => {
  axios
    .get<IPost[]>(...)
    .then(...)
    .catch(ex => {
 const err = axios.isCancel(ex)
 ? "Request cancelled"
 : ex.code === "ECONNABORTED"
 ? "A timeout has occurred"
 : ex.response.status === 404
 ? "Resource not found"
 : "An unexpected error has occurred";
 setError(err);
      setLoading(false);
 });
}, []);
```

1.  现在我们可以继续处理事件处理程序了。这些与类组件实现非常相似，只是用`const`替换了`private`访问修饰符，以及用特定的状态变量和状态设置函数替换了`this.state`和`this.setState`。我们将从取消按钮的点击处理程序开始：

```jsx
const handleCancelClick = () => {
  if (cancelTokenSource) {
    cancelTokenSource.cancel("User cancelled operation");
  }
};
```

1.  接下来，我们可以为标题和正文输入添加更改处理程序：

```jsx
const handleTitleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  setEditPost({ ...editPost, title: e.currentTarget.value });
};

const handleBodyChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
  setEditPost({ ...editPost, body: e.currentTarget.value });
};
```

1.  接下来是保存按钮的点击处理程序：

```jsx
const handleSaveClick = () => {
  if (editPost.id) {
    axios
      .put<IPost>(
        `https://jsonplaceholder.typicode.com/posts/${editPost.id}`,
        editPost,
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      )
      .then(() => {
        setEditPost({
          body: "",
          title: "",
          userId: 1
        });
        setPosts(
          posts.filter(post => post.id !== editPost.id).concat(editPost)
        );
      });
  } else {
    axios
      .post<IPost>(
        "https://jsonplaceholder.typicode.com/posts",
        {
          body: editPost.body,
          title: editPost.title,
          userId: editPost.userId
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      )
      .then(response => {
        setPosts(posts.concat(response.data));
      });
  }
};
```

1.  接下来让我们来处理更新按钮：

```jsx
const handleUpdateClick = (post: IPost) => {
  setEditPost(post);
};
```

1.  最后一个处理程序是用于删除按钮：

```jsx
const handleDeleteClick = (post: IPost) => {
  axios
    .delete(`https://jsonplaceholder.typicode.com/posts/${post.id}`)
    .then(() => {
      setPosts(posts.filter(p => p.id !== post.id));
    });
};
```

1.  我们的最后任务是实现返回语句。同样，这与类组件的`render`方法非常相似，只是去掉了对`this`的引用：

```jsx
return (
  <div className="App">
    <div className="post-edit">
      <input
        type="text"
        placeholder="Enter title"
        value={editPost.title}
        onChange={handleTitleChange}
      />
      <textarea
        placeholder="Enter body"
        value={editPost.body}
        onChange={handleBodyChange}
      />
      <button onClick={handleSaveClick}>Save</button>
    </div>
    {loading && <button onClick={handleCancelClick}>Cancel</button>}
    <ul className="posts">
      {posts.map(post => (
        <li key={post.id}>
          <h3>{post.title}</h3>
          <p>{post.body}</p>
          <button onClick={() => handleUpdateClick(post)}>Update</button>
          <button onClick={() => handleDeleteClick(post)}>Delete</button>
        </li>
      ))}
    </ul>
    {error && <p className="error">{error}</p>}
  </div>
);
```

就是这样！我们与 REST API 交互的函数组件已经完成。如果我们尝试这样做，它应该与以前的行为完全一样。

在与 REST API 交互方面的主要区别在于，我们使用`useEffect`函数来进行 REST API 调用以获取需要呈现的数据。当组件已挂载时，我们仍然会这样做，就像在基于类的组件中一样。这只是一种不同的方式来利用组件的生命周期事件。

# 总结

基于回调的异步代码可能很难阅读和维护。谁花了几个小时来追踪回调式异步代码中错误的根本原因？或者只是花了几个小时来理解一段回调式异步代码试图做什么？幸运的是，现在我们有了编写异步代码的替代方法。

基于 Promise 的函数比基于回调的异步代码有了很大的改进，因为代码更易读，错误处理也更容易。`async`和`await`关键字可以说比基于 Promise 的函数代码更容易阅读异步代码，因为它非常接近同步等效代码的样子。

现代浏览器有一个名为`fetch`的很好的函数，用于与 REST API 进行交互。这是一个基于 Promise 的函数，允许我们轻松地发出请求并很好地管理响应。

`axios`是`fetch`的一种流行替代品。该 API 可以说更清晰，并且允许我们更好地处理 HTTP 错误代码。使用`axios`也可以非常简单地处理超时和取消请求。`axios`也非常友好于 TypeScript，因为类型已经内置到库中。在使用过`axios`和`fetch`之后，你更喜欢哪一个？

我们可以在类组件和函数组件中与 REST API 进行交互。当调用 REST API 以获取数据以在第一个组件渲染中显示时，我们需要等到组件挂载后。在类组件中，我们使用`componentDidMount`生命周期方法来实现这一点。在函数组件中，我们使用`useEffect`函数，将空数组作为第二个参数传递。在两种类型的组件中都有与 REST API 交互的经验后，你会在下一个 React 和 TypeScript 项目中使用哪种组件类型？

REST API 并不是我们可能需要交互的唯一类型的 API。GraphQL 是一种流行的替代 API 服务器。我们将在下一章学习如何与 GraphQL 服务器交互。

# 问题

让我们回答以下问题，以帮助我们对刚学到的知识有更深刻的理解：

1.  如果我们在浏览器中运行以下代码，控制台会输出什么？

```jsx
try {
 setInterval(() => {
  throw new Error("Oops");
 }, 1000);
} catch (ex) {
  console.log("Sorry, there is a problem", ex); 
}
```

1.  假设帖子`9999`不存在，如果我们在浏览器中运行以下代码，控制台会输出什么？

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/9999")
  .then(response => {
    console.log("HTTP status code", response.status);
    return response.json();
  })
  .then(data => console.log("Response body", data))
  .catch (error => console.log("Error", error));
```

1.  如果我们用`axios`做类似的练习，当运行以下代码时，控制台会输出什么？

```jsx
axios
  .get("https://jsonplaceholder.typicode.com/posts/9999")
  .then(response => {
    console.log("HTTP status code", response.status);
  })
  .catch(error => {
    console.log("Error", error.response.status);
  });
```

1.  使用原生的`fetch`而不是`axios`有什么好处？

1.  我们如何在以下`axios`请求中添加一个 Bearer 令牌？

```jsx
axios.get("https://jsonplaceholder.typicode.com/posts/1")
```

1.  我们正在使用以下`axios`的`PUT`请求来更新帖子标题？

```jsx
axios.put("https://jsonplaceholder.typicode.com/posts/1", {
  title: "corrected title", 
  body: "some stuff"
});
```

1.  尽管身体没有改变，但我们只是想要更新标题。我们如何将这个转换为`PATCH`请求，以使这个 REST 调用更有效？

1.  我们已经实现了一个函数组件来显示一个帖子。它使用以下代码从 REST API 获取帖子？

```jsx
React.useEffect(() => {
  axios
    .get(`https://jsonplaceholder.typicode.com/posts/${id}`)
    .then(...)
    .catch(...);
});
```

上述代码有什么问题？

# 进一步阅读

以下链接是本章涵盖的主题的进一步信息的好资源：

+   有关 promises 的更多信息可以在 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) 找到

+   有关 `async` 和 `await` 的其他信息可以在 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function) 找到

+   有关 `fetch` 函数的更多信息可以在 [`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) 找到

+   `axios` 的 GitHub 页面在 [`github.com/axios/axios`](https://github.com/axios/axios) 上
