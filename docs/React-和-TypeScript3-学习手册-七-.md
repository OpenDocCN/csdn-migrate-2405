# React 和 TypeScript3 学习手册（七）

> 原文：[`zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487`](https://zh.annas-archive.org/md5/9ec979022a994e15697a4059ac32f487)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：答案

# 第一章：TypeScript 基础知识

1.  有哪五种原始类型？

+   `string`：表示 Unicode 字符序列

+   `number`：表示整数和浮点数

+   `boolean`：表示逻辑真或假

+   `undefined`：表示尚未初始化的值

+   `null`：表示没有值

1.  在以下代码中，`flag`变量的推断类型将是什么？

```jsx
 const flag = false;
```

`flag`将被推断为`boolean`类型。

1.  接口和类型别名之间有什么区别？

主要区别在于类型别名不能被扩展或实现，就像你可以使用接口一样。

1.  以下是代码中的问题？

```jsx
class Product {
  constructor(public name: string, public unitPrice: number) {}
}

let table = new Product();
table.name = "Table";
table.unitPrice = 700;
```

构造函数需要传递`name`和`unitPrice`。以下是解决问题的两种方法。

在构造函数中传递值：

```jsx
let table = new Product("Table", 700);
```

使参数可选：

```jsx
class Product {
  constructor(public name?: string, public unitPrice?: number) {}
}
```

1.  如果我们希望我们的 TypeScript 程序支持 IE11，`--target`编译器选项应该是什么？

这应该是`es5`，因为 IE11 只支持 ES5 功能。

1.  是否可能让 TypeScript 编译器转译 ES6 JavaScript 文件？如果可以，怎么做？

是的！我们可以使用`--allowJS`设置来让编译器转译 JavaScript 文件。

1.  我们如何防止`console.log()`语句进入我们的代码？

我们可以使用 tslint 和`"no-console"`规则来强制执行。这将是`tslint.json`中的规则：

```jsx
{
 "rules": {
 "no-console": true
 }
}
```

# 第二章：TypeScript 3 中的新功能

1.  我们有一个绘制点的函数：

```jsx
function drawPoint(x: number, y: number, z: number) {
  ...
}
```

我们还有以下`point`变量：

```jsx
const point: [number, number, number] = [100, 200, 300];
```

我们如何以简洁的方式调用`drawPoint`函数？

```jsx
drawPoint(...point);
```

1.  我们需要创建`drawPoint`函数的另一个版本，可以通过传递 x、y 和 z 点值来调用：

```jsx
drawPoint(1, 2, 3);
```

在`drawPoint`的实现内部，我们从元组数据类型`[number, number, number]`中绘制点。如何定义具有所需元组的方法参数？

```jsx
function drawPoint(...point: [number, number, number]) {
  ...
}
```

1.  在你的`drawPoint`实现中，如何使`z`点可选？

```jsx
function drawPoint(...point: [number, number, number?]) {
  ...
}
```

1.  我们有一个名为`getData`的函数，调用 Web API 获取一些数据。不同的 API 资源数量仍在增长，所以我们选择使用`any`作为返回类型：

```jsx
function getData(resource: string): any {
  const data = ... // call the web API
  if (resource === "person") {
    data.fullName = `${data.firstName} ${data.surname}`;
  }
  return data;
}
```

我们如何通过利用`unknown`类型使`getData`更加类型安全？

```jsx
class Person {
 firstName: string;
 surname: string;
 fullName: string;
}

function getData(resource: string): unknown {
  const data = {};
  if (data instanceof Person) {
    data.fullName = `${data.firstName} ${data.surname}`;
  }
  return data;
}
```

1.  我们可以使用哪个`build`标志来确定哪些项目已过时并需要重建，而无需进行重建？

```jsx
tsc --build ... --dry --verbose 
```

# 第三章：使用 React 和 TypeScript 入门

1.  在开发过程中，允许调试器语句和记录到控制台的`TSLint`设置是什么？

```jsx
"rules": {
  "no-debugger": false,
  "no-console": false,
},
```

1.  在 JSX 中，如何在类组件中显示一个名为`buttonLabel`的 prop 的按钮标签？

```jsx
<button>{this.props.buttonLabel}</button>
```

1.  我们如何使`buttonLabel`属性可选并默认为 Do It？

在接口的类型注释之前使用`?`：

```jsx
interface IProps {
  buttonLabel?: string
}
```

在类组件的顶部实现一个静态`defaultProps`对象：

```jsx
public static defaultProps = {
  buttonLabel: "Do it"
};
```

1.  在 JSX 中，如果名为`doItVisible`的状态为 true，我们如何只显示前面的按钮？假设我们已经声明了一个包含`doItVisible`的状态类型，并且它已经在构造函数中初始化了。

```jsx
{this.state.doItVisible && <button>{this.props.buttonLabel}</button>}
```

1.  我们如何为这个按钮创建一个点击处理程序？

```jsx
<button onClick={this.handleDoItClick}>{this.props.buttonLabel}</button>
```

```jsx
private handleDoItClick = () => {
  // TODO: some stuff!
};
```

1.  我们声明了一个包含`doItDisabled`的状态类型。它也在构造函数中初始化了。我们如何在点击后将此状态设置为禁用“Do it”按钮？

```jsx
private handleDoItClick = () => {
  this.setState({doItDisabled: true})
};
```

```jsx
<button disabled={this.state.doItDisabled}>{this.props.buttonLabel}</button>
```

1.  如果按钮被禁用后被点击，点击处理程序仍然会被调用吗？

不

1.  在类组件中，哪个生命周期方法会被用来给我们的 React 组件中的非 React web 组件添加事件处理程序？

`componentDidMount`

1.  然后我们会使用哪个生命周期方法来移除这个事件处理程序？

`componentWillUnmount`

1.  我们有一个名为`Counter`的函数组件。它需要包含一个名为`count`的状态和一个名为`setCount`的更新函数。我们如何定义这个状态并将初始计数默认为 10？

```jsx
const count, setCount = React.useState(10);
```

1.  在前面的`Counter`组件中，我们有一个`decrement`函数，需要将`count`减 1：

```jsx
const decrement = () => {
  // TODO - reduce count by 1
};
```

这可以如何实现？

```jsx
const decrement = () => {
  setCount(count - 1);
};
```

# 第四章：使用 React Router 进行路由

1.  我们有以下显示客户列表的`Route`：

```jsx
<Route path="/customers" component={CustomersPage} />
```

当页面是`"/customers"`时，`CustomersPage`组件会被渲染吗？

是的

1.  当页面是`"/customers/24322"`时，`CustomersPage`组件会被渲染吗？

是的

1.  我们只希望当路径是`"/customers"`时才渲染`CustomersPage`组件。我们如何改变`Route`上的属性来实现这一点？

我们可以使用`exact`属性：

```jsx
<Route exact={true} path="/customers" component={CustomersPage} />
```

1.  什么样的`Route`可以处理路径`"/customers/24322"`？它应该将`"24322"`放在名为`customerId`的路由参数中：

```jsx
<Route exact={true} path="/customers/:customerId" component={CustomerPage} />
```

1.  然后我们可以将`RouteComponentProps`作为`CustomerPage`的 props 类型，并通过`props.match.params.customerId`访问`customerId`。

我们如何捕获不存在的路径，以便通知用户？

确保所有的`Route`组件都包裹在一个`Switch`组件中。然后我们可以在 Switch 中添加一个渲染给用户一个未找到消息的组件作为最后一个`Route`：

```jsx
<Switch>
  <Route path="/customers/:customerId" component={CustomerPage} />
  <Route exact={true} path="/customers" component={CustomersPage} />
  <Route component={NotFoundPage} />
</Switch>
```

1.  我们如何在`CustomersPage`中实现一个`search`查询参数？因此，`"/customers/?search=Cool Company"`将显示名称为 Cool Company 的客户。

首先，我们需要在我们的类中将 props 类型设置为`RouteComponentProps`：

```jsx
import { RouteComponentProps } from "react-router-dom";

class CustomersPage extends React.Component<RouteComponentProps, IState> { ... }
```

我们可以使用`URLSearchParams`来获取`search`查询参数，并在`componentDidMount`生命周期方法中进行搜索：

```jsx
public componentDidMount() {
  const searchParams = new URLSearchParams(props.location.search);
  const search = searchParams.get("search") || "";

  const products = await ... // make web service call to do search

  this.setState({ products });
}
```

1.  过了一会儿，我们决定将`"customer"`路径更改为`"clients"`。我们如何实现这一点，以便用户仍然可以使用现有的`"customer"`路径，但路径会自动重定向到新的`"client"`路径。

我们可以使用`Redirect`组件将旧路径重定向到新路径：

```jsx
<Switch>
 <Route path="/clients/:customerId" component={CustomerPage} />
 <Route exact={true} path="/clients" component={CustomersPage} />

 <Redirect from="/customers/:customerId" to="/clients/:customerId" />
 <Redirect exact={true} from="/customers" to="/clients" />

 <Route component={NotFoundPage} />
</Switch>

```

# 第五章：高级类型

1.  我们有一个表示课程结果的接口如下：

```jsx
interface ICourseMark {
  courseName: string;
  grade: string;
}
```

我们可以如下使用这个接口：

```jsx
const geography: ICourseMark = {
  courseName: "Geography",
  grade: "B"
} 
```

成绩只能是 A、B、C 或 D。我们如何在这个接口的`grade`属性中创建一个更强类型的版本？

我们可以使用联合类型：

```jsx
interface ICourseMark {
  courseName: string;
  grade: "A" | "B" | "C" | "D";
}
```

1.  我们有以下函数，用于验证数字和字符串是否具有值：

```jsx
function isNumberPopulated(field: number): boolean {
  return field !== null && field !== undefined;
}

function isStringPopulated(field: string): boolean {
  return field !== null && field !== undefined && field !== "";
}
```

我们如何将这些组合成一个名为`isPopulated`的单一函数，带有签名重载？

我们可以在主函数中使用重载签名，然后使用联合类型来处理`field`的不同分支逻辑：

```jsx
function isPopulated(field: number): boolean 
function isPopulated(field: string): boolean
function isPopulated(field: number | string): boolean {
 if (typeof field === "number") {
 return field !== null && field !== undefined;
 } else {
 return field !== null && field !== undefined && field !== "";
 }
}
```

1.  我们如何使用泛型实现一个更灵活的`isPopulated`函数版本？

我们可以使用带有`typeof`类型保护的通用函数来处理字符串的特殊代码分支：

```jsx
function isPopulated<T>(field: T): boolean {
  if (typeof field === "string") {
    return field !== null && field !== undefined && field !== "";
  } else {
    return field !== null && field !== undefined;
  }
} 
```

1.  我们有一个名为 stages 的类型别名：

```jsx
type Stages = {
  pending: 'Pending',
  started: 'Started',
  completed: 'Completed',
};
```

我们如何以编程方式将其转换为联合类型`'Pending' | 'Started' | 'Completed'`？

我们可以使用`keyof`关键字：

```jsx
type StageUnion = keyof Stages
```

1.  我们有以下联合类型：

```jsx
type Grade = 'gold' | 'silver' | 'bronze';
```

我们如何以编程方式创建以下类型？

```jsx
type GradeMap = {
  gold: string;
  silver: string;
  bronze: string
};
```

我们可以按以下方式映射类型：

```jsx
type GradeMap = { [P in Grade]: string }
```

# 第六章：组件模式

1.  React 给我们提供了什么特殊属性来访问组件的子元素？

一个名为`children`的属性

1.  有多少个组件可以共享 React 上下文的状态？

在组件层次结构中提供者组件下，我们可以有多少个组件？

1.  在消费 React 上下文时，它使用什么模式允许我们使用上下文渲染我们的内容？

渲染 props 模式

1.  一个组件中可以有多少个渲染 props？

尽可能多

1.  一个组件中有多少个子元素 props？

1

1.  我们只在产品页面上使用了`withLoader`。我们在`ProductData.ts`中有以下函数来获取所有产品：

```jsx
export const getProducts = async (): Promise<IProduct[]> => {
  await wait(1000);
  return products;
};
```

您能使用这个来通过使用`withLoader`HOC 在产品页面上实现一个加载器旋转器吗？

首先，我们将`ProductPage`分成一个容器和一个展示组件。 展示组件将渲染产品列表，并将其导出为包裹在`withLoader`HOC 中的组件：

```jsx
import * as React from "react";
import { Link } from "react-router-dom";
import { IProduct } from "./ProductsData";
import withLoader from "./withLoader";

interface IProps {
  products: IProduct[];
  search: string;
}
const ProductList: React.SFC<IProps> = props => {
  const { products, search } = props;
  return (
    <ul className="product-list">
      {products.map(product => {
        if (
          !search ||
          (search &&
            product.name.toLowerCase().indexOf(search.toLowerCase()) > -1)
        ) {
          return (
            <li key={product.id} className="product-list-item">
              <Link to={`/products/${product.id}`}>{product.name}</Link>
            </li>
          );
        } else {
          return null;
        }
      })}
    </ul>
  );
};

export default withLoader(ProductList);
```

然后我们可以在`ProductPage`中使用它，如其`render`方法中所示：

```jsx
public render() {
 return (
 <div className="page-container">
 <p>
 Welcome to React Shop where you can get all your tools for ReactJS!
 </p>
 <ProductList
 loading={this.state.loading}
 products={this.state.products}
 search={this.state.search}
 />
 </div>
 );
}
```

1.  是否可能使用 children props 模式创建一个加载器旋转器？ 因此，消费 JSX 将类似于这样：

```jsx
<Loader loading={this.state.loading}>
  <div>
    The content for my component ...
  </div>
</Loader>
```

如果可以的话，试着实现一下？

是的

```jsx
import * as React from "react";

interface IProps {
  loading: boolean;
}

const Loader: React.SFC<IProps> = props =>
  props.loading ? (
    <div className="loader-overlay">
      <div className="loader-circle-wrap">
        <div className="loader-circle" />
      </div>
    </div>
  ) : props.children ? (
    <React.Fragment>{props.children}</React.Fragment>
  ) : null;

export default Loader;
```

# 第七章：处理表单

1.  扩展我们的通用`Field`组件，使用原生数字输入包括一个数字编辑器。

+   首先，在`type`属性中添加`"Number"`：

```jsx
interface IFieldProps {
  ...
  type?: "Text" | "Email" | "Select" | "TextArea" | "Number";
}
```

+   在渲染`input`时包括`"Number"`类型：

```jsx
{(type === "Text" || type === "Email" || type === "Number") && (
  <input
    type={type.toLowerCase()}
    id={name}
    value={context.values[name]}
    onChange={e => handleChange(e, context)}
    onBlur={e => handleBlur(e, context)}
  />
)}
```

1.  在“联系我们”表单上实现一个紧急性字段，以指示回复的紧急程度。 该字段应为数字。

在 notes 字段之后立即添加以下字段：

```jsx
<Form.Field name="urgency" label="How urgent is a response?" type="Number" />
```

1.  在通用`Form`组件中实现一个新的验证函数，验证一个数字是否在另外两个数字之间。

在`Form.tsx`中添加以下函数：

```jsx
export const between: Validator = (
  fieldName: string,
  values: IValues,
  bounds: { lower: number; upper: number }
): string =>
  values[fieldName] &&
  (values[fieldName] < bounds.lower || values[fieldName] > bounds.upper)
    ? `This must be between ${bounds.lower} and ${bounds.upper}`
    : "";
```

1.  实现一个紧急性字段的验证规则，以确保它在 1 到 10 之间。

+   首先在`ContactUs.tsx`中导入`between`验证器：

```jsx
import { between, Form, ISubmitResult, IValues, minLength, required } from "./Form";
```

+   在`ContactUs.tsx`中的`validationRules`属性中添加紧急性规则：

```jsx
validationRules={{
  email: { validator: required },
  name: [{ validator: required }, { validator: minLength, arg: 3 }],
  urgency: [{ validator: between, arg: { lower: 1, upper: 10 } }]
}}
```

1.  当用户在不输入任何内容的情况下点击并离开字段时，我们的验证会触发。 我们如何才能触发验证，当字段失去焦点但只有在它被更改时？ 尝试实现一下这个。

+   我们需要跟踪表单状态中的字段是否被触摸：

```jsx
interface ITouched {
 [key: string]: boolean;
}

interface IState {
```

```jsx
  touched: ITouched;
  ...
}
```

+   我们在构造函数中将每个字段的`touched`值初始化为`false`：

```jsx
constructor(props: IFormProps) {
  super(props);
  const errors = {};
  const touched = {};
  Object.keys(props.defaultValues).forEach(fieldName => {
    errors[fieldName] = [];
    touched[fieldName] = false;
  });
  this.state = {
    errors,
    submitted: false,
    submitting: false,
    touched,
    values: props.defaultValues
  };
}
```

+   在`setValue`方法中，我们更新正在更新的字段的`touched`值为`true`：

```jsx
private setValue = (fieldName: string, value: any) => {
  const newValues = { ...this.state.values, [fieldName]: 
   value };
  const newTouched = { ...this.state.touched, [fieldName]:  
   true };
  this.setState({ values: newValues, touched: newTouched });
};
```

+   在 validate 方法的顶部，我们检查字段是否被触摸，如果没有，我们返回一个空数组来指示字段是有效的：

```jsx
private validate = (fieldName: string, value: any): string[] => {
  if (!this.state.touched[fieldName]) {
    return [];
  }
  ...
};
```

# 第八章：React Redux

1.  操作对象中的`type`属性是必需的吗？ 这个属性需要被称为`type`吗？ 我们可以称它为其他名称吗？

操作对象中`type`属性是必需的，并且必须称为`type`。

1.  操作对象可以包含多少属性？

我们可以有很多！它需要至少包括一个`type`属性。然后可以包括我们需要的其他属性，以便减少状态的改变，但这通常被合并在一个额外的属性中。因此，通常一个动作会有一个或两个属性。

1.  什么是动作创建者？

动作创建者是返回动作对象的函数。组件调用这些函数以改变存储中的状态。

1.  为什么我们在 React 商店应用程序的 Redux 存储中需要 Redux Thunk？

默认情况下，Redux 存储无法管理异步动作创建者。需要向 Redux 存储添加中间件以便促进异步动作创建者。Redux Thunk 是我们添加的中间件来实现这一点。

1.  除了 Redux Thunk 之外，我们还能用其他东西吗？

是的！我们可以创建自己的中间件。还有其他成熟的库，比如 Redux Saga，我们也可以使用。

1.  在我们刚刚实现的`basketReducer`中，为什么我们不直接使用`push`函数将项目添加到篮子状态中？高亮显示的行有什么问题？

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
```

```jsx
  return state || initialBasketState;
};
```

这直接改变了产品的状态，并使函数变得不纯。这是因为我们改变了状态参数，它存在于函数范围之外。在这种情况下违反了这个规则，导致当单击“添加到篮子”按钮时，篮子摘要在渲染页面上不会增加。

# 第九章：与 RESTful API 交互

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

我们会收到一条消息，说发生了一个未捕获的错误（Oops）。`console.log`语句将不会被执行。

1.  假设帖子 9999 不存在，如果我们在浏览器中运行以下代码，控制台会输出什么：

```jsx
fetch("https://jsonplaceholder.typicode.com/posts/9999")
  .then(response => {
    console.log("HTTP status code", response.status);
    return response.json();
  })
  .then(data => console.log("Response body", data))
  .catch (error => console.log("Error", error));
```

！[](assets/5e6e8f9f-dbfa-40f8-927c-05b97d901a61.png)

关键是，使用`fetch`函数时，HTTP 错误不会在`catch`方法中处理。

1.  如果我们使用`axios`进行类似的练习，运行以下代码时控制台会输出什么？

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

！[](assets/3d06e29a-9e9a-45e6-82e9-dcdaa2d86a29.png)

关键是，HTTP 错误确实在`catch`方法中使用`axios`处理。

1.  使用本机`fetch`而不是`axios`的好处是什么？

如果我们的目标是现代浏览器（而不是 IE），并且只需要简单的 REST API 交互，那么`fetch`可能比`axios`更受欢迎，因为我们的代码不依赖于第三方代码。它也可能运行得更快，因为执行的非本地代码更少。

1.  如何在以下`axios`请求中添加一个 Bearer 令牌？

```jsx
axios.get("https://jsonplaceholder.typicode.com/posts/1")
```

1.  第二个参数是一个对象文字，其中有一个`header`属性，可以包含请求的 HTTP 标头：

```jsx
axios
  .get("https://jsonplaceholder.typicode.com/posts/1", {
    headers: {
      "Authorization": `Bearer ${token}`
    }
  });
```

1.  我们正在使用以下`axios`的`PUT`请求来更新帖子标题：

```jsx
axios.put("https://jsonplaceholder.typicode.com/posts/1", {
  title: "corrected title", 
  body: "some stuff"
});
```

尽管主体没有改变 - 我们只是想要更新标题。我们如何将其更改为`PATCH`请求，以使此 REST 调用更有效？

```jsx
axios.patch("https://jsonplaceholder.typicode.com/posts/1", {
  title: "corrected title"
});
```

1.  我们已经实现了一个函数组件来显示一个帖子。它使用以下代码从 REST API 获取帖子：

```jsx
React.useEffect(() => {
  axios
    .get(`https://jsonplaceholder.typicode.com/posts/${id}`)
    .then(...)
    .catch(...);
});
```

上述代码有什么问题？

`useEffect`函数的第二个参数丢失，这意味着每次组件呈现时都会调用 REST API。应该提供一个空数组作为第二个参数，以便 REST API 仅在第一次呈现时被调用：

```jsx
React.useEffect(() => {
  axios
    .get(`https://jsonplaceholder.typicode.com/posts/${id}`)
    .then(...)
    .catch(...);
}, []);
```

# 第十章：与 GraphQL API 交互

1.  在 GitHub GraphQL Explorer 中，创建一个查询，返回 React 项目中最后五个未解决的问题。在响应中返回问题标题和 URL：

```jsx
query { 
  repository (owner:"facebook", name:"react") {
    issues(last: 5, states:[OPEN]) {
      edges {
        node {
          title
          url
        }
      }
    }
  }
}
```

1.  增强最后一个查询，使返回的问题数量成为一个参数，并将其默认值设置为 5：

```jsx
query ($lastCount: Int = 5) { 
  repository (owner:"facebook", name:"react") {
    issues(last: $lastCount, states: [OPEN]) {
      edges {
        node {
          title
          url
        }
      }
    }
  }
}
```

1.  在 GitHub GraphQL Explorer 中创建一个突变，取消对一个星标存储库的标记。该突变应该将存储库 ID 作为参数：

```jsx
mutation ($repoId: ID!) {
  removeStar(input: { starrableId: $repoId }) {
    starrable {
      stargazers {
        totalCount
      }
    }
  }
}
```

1.  GraphQL 查询放在 HTTP 请求的哪一部分？

HTTP 主体

1.  GraphQL 突变放在 HTTP 请求的哪一部分？

HTTP 主体

1.  我们如何使来自`react-apollo`的`Query`组件的响应类型安全？

创建另一个组件，扩展`Query`，将结果的类型作为泛型参数传入：

```jsx
class MyQuery extends Query<IResult> {}
```

然后我们可以在 JSX 中使用`MyQuery`组件。

1.  使用`react-boost`脚手架项目时，默认情况下是否启用缓存？

开启

1.  我们可以在`Mutation`组件上使用哪个属性来更新本地缓存？

`update`属性。

# 第十一章：使用 Jest 进行单元测试

1.  假设我们正在实现一个 Jest 测试，并且有一个名为`result`的变量，我们想检查它不是`null`。我们如何使用 Jest 匹配器函数来实现这一点？

```jsx
expect(result).not.toBeNull()
```

1.  假设我们有一个名为`person`的变量，类型为`IPerson`：

```jsx
interface IPerson {
  id: number;
  name: string;
}
```

我们想要检查`person`变量是否为`{ id: 1, name: "bob" }`。我们如何使用 Jest 匹配器函数来实现这一点？

```jsx
expect(person).not.toBeEqual({ id: 1, name: "bob" });
```

1.  在上一题中，我们是否可以通过 Jest 快照测试来进行我们的检查？如果可以，如何进行？

是的：

```jsx
expect(person).toMatchSnapshot();
```

1.  我们实现了一个名为`CheckList`的组件，它从数组中以列表的形式呈现文本。每个列表项都有一个复选框，以便用户可以选择列表项。该组件有一个名为`onItemSelect`的函数 prop，当用户通过选中复选框选择项目时会调用该函数。我们正在实施一个测试来验证`onItemSelect`prop 是否起作用。以下代码行在测试中呈现组件：

```jsx
const { container } = render(<SimpleList data={["Apple", "Banana", "Strawberry"]} onItemSelect={handleListItemSelect} />);
```

我们如何使用 Jest 模拟函数来检查`handleListItemSelect`是否被调用？

```jsx
const handleListItemSelect = jest.fn();
const { container } = render(<SimpleList data={["Apple", "Banana", "Strawberry"]} onItemSelect={handleListItemSelect} />);

// TODO - select the list item

expect(handleListItemSelect).toBeCalledTimes(1);
```

1.  在上一题中的`SimpleList`的实现中，`onItemSelect`函数接受一个名为`item`的参数，这是用户选择的`string`值。在我们的测试中，假设我们已经模拟用户选择了`"Banana"`。我们如何检查`onItemSelect`函数是否被调用，并且参数为`"Banana"`？

```jsx
expect(handleListItemSelect).toBeCalledWith("Banana");
```

1.  在上两题中的`SimpleList`的实现中，文本是使用与复选框绑定的标签显示的，使用了`for`属性。我们如何使用 React Testing Library 中的函数来首先定位`"Banana"`复选框，然后对其进行检查？

```jsx
const checkbox = getByLabelText("Banana") as HTMLInputElement;
fireEvent.change(checkbox, {
  target: { checked: true }
});
```

1.  在本章中，我们发现从 JSONPlaceholder REST API 渲染帖子的代码覆盖率很低。其中一个未覆盖的领域是在从 REST API 获取帖子时，在`componentDidMount`函数中处理 HTTP 错误代码。创建一个测试来覆盖这部分代码：

```jsx
test("When the post GET request errors when the page is loaded, an error is shown", async () => {
  const mock = new MockAdapter(axios);
  mock.onGet("https://jsonplaceholder.typicode.com/posts").reply(404);

  const { getByTestId } = render(<App />);

  const error: any = await waitForElement(() => getByTestId("error"));

  expect(error).toMatchSnapshot();
});
```

需要向`App`组件代码添加一个测试 ID：

```jsx
{this.state.error && <p className="error" data-testid="error">{this.state.error}</p>}
```
