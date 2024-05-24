# React 项目（四）

> 原文：[`zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0`](https://zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 React Native 和 GraphQL 构建全栈电子商务应用程序

如果您正在阅读本文，这意味着您已经到达了本书的最后部分，该部分使用 React 构建 Web 应用程序。在前面的章节中，您已经使用了 React 的核心功能，如渲染组件、使用 Context 进行状态管理和 Hooks。您已经学会了如何创建 PWA 和 SSR 应用程序，以及如何将路由添加到您的 React 应用程序中。此外，您还知道如何使用 Jest 和 Enzyme 向 React 应用程序添加测试。让我们将 GraphQL 添加到您迄今为止学到的东西列表中。

在本章中，您不仅将构建应用程序的前端，还将构建后端。为此，将使用 GraphQL，它最好被定义为 API 的查询语言。使用模拟数据和 Apollo Server，您将扩展一个 GraphQL 服务器，为您的 React 应用程序公开一个单一的端点。在前端方面，将使用 Apollo Client 来消耗此端点，它将帮助您处理向服务器发送请求以及此数据的状态管理。

本章将涵盖以下主题：

+   使用 GraphQL 查询和变异数据

+   使用 Apollo Client 消耗 GraphQL

+   使用 GraphQL 处理状态管理

# 项目概述

在本章中，我们将创建一个全栈电子商务应用程序，后端使用 GraphQL 服务器，并在 React 中使用 Apollo Client 消耗此服务器。对于后端和前端，都有一个初始应用程序可供您快速开始。

构建时间为 3 小时。

# 入门

在本章中，我们将创建的项目是基于 GitHub 上可以找到的初始版本构建的：[`github.com/PacktPublishing/React-Projects/tree/ch7-initial`](https://github.com/PacktPublishing/React-Projects/tree/ch7-initial)。完整的源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch7`](https://github.com/PacktPublishing/React-Projects/tree/ch7)。

初始项目包括一个基于 Create React App 的样板应用程序，可以让您快速开始，并且一个 GraphQL 服务器，您可以在本地运行。您可以在`client`目录中找到应用程序，`server`目录中可以找到 GraphQL 服务器。初始应用程序和 GraphQL 服务器都需要安装依赖项，并且在开发过程中需要始终运行，您可以通过在`client`和`server`目录中运行以下命令来实现：

```jsx
npm install && npm start
```

该命令将安装运行 React 应用程序和 GraphQL 服务器所需的所有依赖项，包括`react`，`react-scripts`，`graphql`和`apollo-server`。如果您想了解安装的所有依赖项，请查看`client`和`server`目录中的`package.json`文件。

安装过程完成后，将启动 GraphQL 服务器和 React 应用程序。

# 开始使用初始 React 应用程序

由于 React 应用程序是由 Create React App 创建的，它将自动在浏览器中启动，网址是`http://localhost:3000/`。这个初始应用程序不显示任何数据，因为它仍然需要连接到 GraphQL 服务器，这将在本章后面进行。因此，此时应用程序将仅呈现一个标题为 Ecommerce Store 的标题和一个子标题，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/63e36de1-c18c-4f1d-9701-6906f169f375.png)

这个初始 React 应用程序的结构如下：

```jsx
ecommerce-store
|-- client
    |-- node_modules
    |-- public
        |-- favicon.ico
        |-- index.html
        |-- manifest.json
    |-- src
        |-- components
            |-- Button
                |-- Button.js
            |-- Cart
                |-- Cart.js
                |-- CartButton.js
                |-- Totals.js
            |-- Header
                |-- Header.js
                |-- SubHeader.js
            |-- Products
                |-- ProductItem.js
                |-- Products.js
            |-- App.js
        |-- index.js
        |-- serviceWorker.js
    |-- package.json
```

在`client/src`目录中，您将找到应用程序的入口点，即`index.js`。该文件将引用`App.js`中的`App`组件。`App`组件具有一个`Router`组件，根据用户访问的 URL，它将呈现`Products`或`Cart`组件。当未指定特定路由时，将呈现`Products`组件，其中包括`SubHeader`组件，带有指向`Cart`组件的`Button`，以及返回显示产品信息的`ProductItem`组件列表的`map`函数。`/cart`路由将呈现`Cart`组件，该组件还具有`SubHeader`，这次带有返回到上一页的`Button`。同样，将返回产品列表，并且`Totals`组件将显示购物车中产品的总数。

# 开始使用 GraphQL 服务器

虽然您不会对 GraphQL 服务器进行任何代码更改，但了解服务器的运行方式和 GraphQL 的基本概念是很重要的。

GraphQL 最好被描述为 API 的查询语言，并被定义为从 API 检索数据的约定。通常，GraphQL API 被比作 RESTful API，后者是发送 HTTP 请求的众所周知的约定，这些请求依赖于多个端点，这些端点将返回单独的数据集。与众所周知的 RESTful API 相反，GraphQL API 将提供一个单一的端点，让您查询和/或改变数据源，比如数据库。您可以通过向 GraphQL 服务器发送包含查询或变异操作的文档来查询或改变数据。无论可用的数据是什么，都可以在 GraphQL 服务器的模式中找到，该模式由定义可以查询或改变的数据的类型组成。

GraphQL 服务器可以在 `server` 目录中找到，并为您在本章中构建的前端 React 应用程序提供后端支持。该服务器使用 Express 和 Apollo Server 创建，其中 Express 是一个使用 JavaScript 创建 API 的框架，而 Apollo Server 是一个开源包，可以帮助您使用有限的代码创建 GraphQL 服务器。确保您已在 `server` 目录中运行了 `npm install` 和 `npm start` 命令后，GraphQL API 就可以在 `http://localhost:4000/graphql` 上使用。Apollo Server 默认会在端口 `4000` 上运行您的 GraphQL 服务器。在浏览器的这个页面上，将显示 GraphQL Playground，您可以在其中使用和探索 GraphQL 服务器。以下是该 Playground 的示例截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/2cee33f7-0d54-4d36-9b16-c3a05978bb0e.png)

通过这个 Playground，您可以向 GraphQL 服务器发送查询和变异，您可以在本页面的左侧输入。您可以在此 GraphQL 服务器的 SCHEMA 中找到可以发送的查询和变异，点击标有 SCHEMA 的绿色按钮即可找到。该按钮将打开 SCHEMA 的概述，显示 GraphQL 服务器的所有可能返回值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/77154966-8d2a-4b7f-8485-4931c58619bb.png)

每当您在此页面的左侧描述查询或突变时，服务器返回的输出将显示在播放器的右侧。构造 GraphQL 查询的方式将决定返回数据的结构，因为 GraphQL 遵循“请求所需内容，获得确切内容”的原则。由于 GraphQL 查询始终返回可预测的结果，这意味着我们可以有这样的查询：

```jsx
query {
  products {
    id
    title
    thumbnail
  }
}
```

这将返回一个输出，其结构将遵循您发送到 GraphQL 服务器的文档中定义的查询的相同结构，并具有以下格式：

```jsx
{
  "data": {
    "products": [
      {
        "id": 16608,
        "title": "Awesome Rubber Shoes",
        "thumbnail": "http://lorempixel.com/400/400/technics"
      },
      {
        "id": 20684,
        "title": "Refined Soft Table",
        "thumbnail": "http://lorempixel.com/400/400/fashion"
      }
    ]
  }
}
```

使用 GraphQL 的应用程序通常快速且稳定，因为它们控制获取的数据，而不是服务器。

在下一节中，您将使用 Apollo 将 GraphQL 服务器连接到 React Web 应用程序，并从应用程序向服务器发送文档。

# 使用 React、Apollo 和 GraphQL 构建全栈电子商务应用程序

在本节中，您将连接 React Web 应用程序到 GraphQL 服务器。Apollo Server 用于创建一个使用动态模拟数据作为源的单个 GraphQL 端点。React 使用 Apollo Client 来消耗此端点并处理应用程序的状态管理。

# 将 GraphQL 添加到 React 应用程序

GraphQL 服务器已经就位，让我们继续进行从 React 应用程序向该服务器发出请求的部分。为此，您将使用 Apollo 软件包，该软件包可帮助您在应用程序和服务器之间添加一个抽象层。这样，您就不必担心自己通过例如`fetch`发送文档到 GraphQL 端点，而是可以直接从组件发送文档。

如前所述，您可以使用 Apollo 连接到 GraphQL 服务器；为此，将使用 Apollo Client。使用 Apollo Client，您可以建立与服务器的连接，处理查询和突变，并为从 GraphQL 服务器检索的数据启用缓存，等等。通过以下步骤将 Apollo Client 添加到您的应用程序：

1.  要安装 Apollo Client 及其相关软件包，您需要在初始化 React 应用程序的`client`目录中运行以下命令：

```jsx
npm install apollo-client apollo-link-http react-apollo graphql graphql-tag
```

这将安装不仅 Apollo Client，还将安装您在 React 应用程序中使用 Apollo Client 和 GraphQL 所需的其他依赖项：

+   `apollo-link-http`将与 GraphQL 服务器连接

+   `react-apollo`将提供您发送查询和突变以及处理数据流所需的组件。

+   `graphql`和`graphql-tag`将处理 GraphQL 并编写查询语言

1.  这些包应该被导入到您想要创建 Apollo Client 的文件中，在这种情况下，将是`client/src/App.js`：

```jsx
import React from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import { Route, Switch } from 'react-router-dom';
import Header from './Header/Header';
import Products from './Products/Products';
import Cart from './Cart/Cart';

import ApolloClient from 'apollo-client';
import { HttpLink } from 'apollo-link-http';
import { ApolloProvider } from 'react-apollo';

const GlobalStyle = createGlobalStyle`
    ...
```

1.  现在，您可以使用`ApolloClient`类定义`client`常量，并使用`HttpLink`与 GraphQL 服务器建立连接；因此，可以创建如下的`client`常量：

```jsx
import React from 'react';
import styled, { createGlobalStyle } from 'styled-components';
import { Route, Switch } from 'react-router-dom';
import Header from './Header/Header';
import Products from './Products/Products';
import Cart from './Cart/Cart';

import ApolloClient from 'apollo-client';
import { InMemoryCache } from 'apollo-cache-inmemory';
import { HttpLink } from 'apollo-link-http';
import { ApolloProvider } from 'react-apollo';

const client = () => new ApolloClient({
 link: new HttpLink({
 uri: 'http://localhost:6000',
 }),
});

const GlobalStyle = createGlobalStyle`
    ...
```

1.  在`App`组件的`return`函数中，您需要添加`ApolloProvider`并将刚刚创建的`client`作为属性传递：

```jsx
...
const App = () => (
-  <>
+  <ApolloProvider client={client}>
     <GlobalStyle />
       <AppWrapper>
       <Header />
       <Switch>
         <Route exact path='/' component={Products} />
         <Route path='/cart' component={Cart} />
       </Switch>
     </AppWrapper>
-  </>
+  </ApolloProvider>
);

export default App;
```

经过这些步骤，所有嵌套在`ApolloProvider`中的组件都可以访问此`client`并发送带有查询和/或突变的文档到 GraphQL 服务器。从`ApolloProvider`获取数据的方法类似于上下文 API 与上下文值的交互，并将在本节的下一部分中进行演示。

# 使用 React 发送 GraphQL 查询

`react-apollo`包不仅导出 Provider，还导出了从此 Provider 中消耗值的方法。这样，您可以使用添加到 Provider 的客户端轻松获取任何值。其中之一是`Query`，它可以帮助您发送包含查询的文档到 GraphQL 服务器，而无需使用`fetch`函数，例如。

由于`Query`组件应始终嵌套在`ApolloProvider`组件内，它们可以放置在已在`App`中呈现的任何组件中。其中之一是`client/src/components/Product/Products.js`中的`Products`组件。该组件被呈现为`/`路由，并应显示电子商务商店中可用的产品。

要从`Products`组件发送文档，请按照以下步骤进行操作，这些步骤将指导您使用`react-apollo`发送文档的过程：

1.  可以使用播放器中的内省方法或`server/typeDefs.js`文件找到从 GraphQL 服务器获取产品的查询，并且如下所示：

```jsx
query {
  products {
    id
    title
    thumbnail
  }
}
```

使用查询将此文档发送到 GraphQL 服务器将返回一个由产品信息对象组成的数组，默认情况下每次返回 10 个产品。结果将以 JSON 格式返回，并且每次发送请求时都会包含不同的产品，因为数据是由 GraphQL 服务器模拟的。

1.  在`Products`组件中，您可以从`react-apollo`导入`Query`组件并为命名为`getProducts`的查询定义一个常量。此外，您需要从`graphql-tag`导入`gql`，以在 React 文件中使用 GraphQL 查询语言，如下所示：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Query } from 'react-apollo';
import gql from 'graphql-tag';
import SubHeader from '../Header/SubHeader';
import ProductItem from './ProductItem';

const GET_PRODUCTS = gql`
 query getProducts {
 products {
 id
 title
 thumbnail
 }
 }
`;

export const ProductItemsWrapper = styled.div`
    ...
```

1.  导入的`Query`组件可以从`Products`返回，并根据您作为 prop 传递给它的查询处理数据获取过程。与上下文 API 一样，`Query`可以通过返回`data`变量来消耗 Provider 中的数据。您可以遍历此对象中的`products`字段，并通过添加`Query`组件返回`ProductItem`组件的列表：

```jsx
...
const Products = ({ match, history, loading, error, products }) => {
-  const isEmpty = products.length === 0 ? 'No products available' : false;

  return (
    <>
      {history && (
        <SubHeader title='Available products' goToCart={() => history.push('/cart')} />
      )} -      {!loading && !error && !isEmpty ? (
+      <Query query={GET_PRODUCTS}>
+        {({ data }) => {
+          return (             <ProductItemsWrapper>
               {data.products && data.products.map(product => (
                 <ProductItem key={product.id} data={product} />
               ))}
             </ProductItemsWrapper> +          );
+        }}
+      </Query>
-      ) : (
-        <Alert>{loading ? 'Loading...' : error || isEmpty}</Alert>
-      )}
    </>
  );
};
...
```

1.  `Query`组件不仅会返回一个`data`对象，还会返回`loading`和`error`变量。因此，您可以使用这个值而不是为`loading` prop 设置默认值，并在其值为`true`时返回加载消息。对于`error`变量，您也可以采用相同的方法。此外，`Products` prop 的默认值不再使用，可以删除：

```jsx
- const Products = ({ match, history, loading, error, products }) => {
-   return (
+ const Products = ({ match, history }) => (
  <>
    {history && (
      <SubHeader title='Available products' goToCart={() => history.push('/cart')} />
    )}
    <Query query={GET_PRODUCTS}>
-       {({ data }) => {
+       {({ loading, error, data }) => {
+         if (loading || error) {
+           return <Alert>{loading ? 'Loading...' : error}</Alert>;
+         }
          return (
            <ProductItemsWrapper>
              {data.products && data.products.map(product => (
                <ProductItem key={product.id} data={product} />
              ))}
            </ProductItemsWrapper>
          );
        }}
      </Query>
  </>
);
- };

- Products.defaultProps = {
-   loading: false,
-   error: '',
-   products: [],
- }
```

当您的应用程序挂载并随后在`ProductItem`组件的列表中显示产品信息时，将向 GraphQL 服务器发送带有`GET_PRODUCTS`查询的文档。在添加逻辑以从 GraphQL 服务器检索产品信息之后，您的应用程序将类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/9ed5e8e6-fb2d-4da5-a311-f510e4fede79.png)

由于`/cart`路由上的`Cart`组件还需要从 GraphQL 服务器查询数据，因此还应该对`src/components/Cart/Cart.js`文件进行更改。就像我们为`Products`所做的那样，应该添加一个`Query`组件来从服务器检索数据，并且可以通过以下步骤完成：

1.  首先导入发送查询到 GraphQL 服务器所需的依赖项，即`react-apollo`以获取`Query`组件和`graphql-tag`以使用 GraphQL 查询语言来定义要发送到 GraphQL 的查询。

```jsx
import React from 'react';
import styled from 'styled-components';
+ import { Query } from 'react-apollo';
+ import gql from 'graphql-tag';
import SubHeader from '../Header/SubHeader';
import ProductItem from '../Products/ProductItem';
import Totals from './Totals';

const CartWrapper = styled.div`
    ...
```

1.  完成后，您可以定义`query`，应该在文档中发送。这将检索`cart`的信息，包括可能在`cart`中的任何`products`：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Query } from 'react-apollo';
import gql from 'graphql-tag';
import SubHeader from '../Header/SubHeader';
import ProductItem from '../Products/ProductItem';
import Totals from './Totals';

+ const GET_CART = gql`
+  query getCart {
+    cart {
+      total
+      products {
+        id
+        title
+        thumbnail
+      }
+    }
+  } + `; const CartWrapper = styled.div`
    ...
```

1.  用以下内容替换`Cart`组件的现有代码，其中实现了`Query`组件，而`Cart`组件仅接收`match`和`history` props。因此，您需要用以下内容替换此组件的代码：

```jsx
...

- const Cart = ...

+ const Cart = ({ match, history }) => (
+  <>
+    {history && (
+      <SubHeader goBack={() => history.goBack()} title='Cart' />
+    )}
+    <Query query={GET_CART}>
+      {({ loading, error, data }) => {
+        if (loading || error) {
+          return <Alert>{loading ? 'Loading...' : error}</Alert>;
+        }
+        return (
+          <CartWrapper>
+            <CartItemsWrapper>
+              {data.cart && data.cart.products.map(product => (
+                <ProductItem key={product.id} data={product} />
+              ))}
+            </CartItemsWrapper>
+            <Totals count={data.cart.total} />
+          </CartWrapper>
+        );
+      }}
+    </Query>
+  </>
+ );

export default Cart;

...
```

1.  由于购物车是空的，所以现在不会显示任何产品；购物车将在下一节中填满产品。然而，让我们继续在`SubHeader`的`/`路由中为购物车的按钮添加一个`Query`组件，以及一个占位符计数。因此，在`client/src/components/Cart`目录中可以创建一个名为`CartButton.js`的新文件。在这个文件中，一个`Query`组件将从一个查询中返回购物车中产品的总数。此外，我们可以通过在这个文件中添加以下代码来为`Button`组件添加一个值：

```jsx
import React from 'react'
import { Query } from 'react-apollo';
import gql from 'graphql-tag';
import Button from '../Button/Button';

const GET_CART_TOTAL = gql`
  query getCartTotal {
    cart {
      total
    }
  }
`;

const CartButton = ({ onClick }) => (
  <Query query={GET_CART_TOTAL}>
    {({ data, loading, error }) => (
      <Button onClick={onClick}>
        {`Cart (${(loading || error) ? 0 : data && data.cart.total})`}
      </Button>
    )}
  </Query>
);

export default CartButton
```

1.  这个`CartButton`组件替换了`Button`，现在在`client/src/components/Header/SubHeader.js`文件中显示为购物车中产品数量的占位符计数：

```jsx
import React from 'react';
import styled from 'styled-components';
import Button from '../Button/Button';
+ import CartButton from '../Cart/CartButton'; ...

const SubHeader = ({ goBack, title, goToCart = false }) => (
  <SubHeaderWrapper>
    {goBack && <SubHeaderButton onClick={goBack}>{`< Go Back`}</SubHeaderButton>}
    <Title>{ title }</Title>
-    {goToCart && <SubHeaderButton onClick={goToCart}>{`Cart (0)`}</SubHeaderButton>}
+    {goToCart && <CartButton onClick={goToCart} />}
  </SubHeaderWrapper>
);

export default SubHeader;
```

所有显示产品或购物车信息的组件都连接到 GraphQL Client，你可以继续添加将产品添加到购物车的变异。如何将变异添加到应用程序并将文档容器变异发送到 GraphQL 服务器将在本节的最后部分中展示。

# 使用 Apollo Client 处理变异

数据的变异使得使用 GraphQL 更加有趣，因为当数据发生变异时，一些副作用应该被执行。例如，当用户将产品添加到购物车时，购物车的数据也应该在整个组件中更新。当你使用 Apollo Client 时，这是相当容易的，因为 Provider 以与上下文 API 相同的方式处理这个问题。

在编写第一个变异之前，应该将购物车的可执行查询的定义移动到一个常量文件中。这样，你就可以轻松地将它们导入到其他组件中以便重用，并将它们作为副作用执行。创建新的常量文件并将所有的 GraphQL 查询和变异移动到其中需要我们做出以下更改：

1.  在`client/src`目录中，你应该创建一个名为`constants.js`的新文件，并将两个已经定义的查询放在这里，这些查询可以在`Cart`和`CartButton`组件中找到。此外，你需要导入`graphql-tag`，以便在新创建的文件中添加以下代码块来使用 GraphQL 查询语言：

```jsx
import gql from 'graphql-tag';

export const GET_CART_TOTAL = gql`
  query getCartTotal {
    cart {
      total
    }
  }
`;

const GET_CART = gql`
  query getCart {
    cart {
      total
      products {
        id
        title
        thumbnail
      }
    }
  }
`;

export default GET_CART
```

1.  在`Cart`组件中，你可以删除对`GET_CART`的定义，并在`client/src/components/Cart/Cart.js`文件中从`client/src/constants.js`导入该定义：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Query } from 'react-apollo';
- import gql from 'graphql-tag';
import SubHeader from '../Header/SubHeader';
import ProductItem from '../Products/ProductItem';
import Totals from './Totals';
+ import { GET_CART } from '../../constants';

- const GET_CART = gql`
-  query getCart {
-    cart {
-      total
-      products {
-        id
-        title
-        thumbnail
-      }
-    }
-  }
- `;

const CartWrapper = styled.div`
  ...
```

1.  对于`CartButton.js`中的`CartButton`组件，您应该应用相同的更改，但这次是针对`GET_CART_TOTAL`查询，它也可以从`constants`文件中导入，并从`CartButton.js`文件中删除：

```jsx
import React from 'react'
import { Query } from 'react-apollo';
- import gql from 'graphql-tag';
import Button from '../Button/Button';
+ import { GET_CART_TOTAL } from '../../constants';

- const GET_CART_TOTAL = gql`
-   query getCartTotal {
-    cart {
-      total
-    }
-  }
- `;

const CartButton = ({ onClick }) => (
  ...
```

任何与目录中的组件相关的查询或变异的新定义都应从现在开始放在这个文件中。

由于您希望用户能够将产品添加到购物车，因此可以在此文件中添加一个变异的定义。添加产品到购物车的变异如下，它需要`productId`参数来将产品添加到购物车。以下变异可以返回购物车的字段，就像查询一样：

```jsx
mutation addToCart($productId: Int!) {
    addToCart(input: { productId: $productId }) {
        total
    }
  }
```

您可以通过在`http://localhost:4000/graphql`上可用的 GraphQL Playground 上尝试此变异来测试此变异。在这里，您需要在此页面的左上角框中添加变异。您想要包含在此变异中的`productId`变量必须放在此页面的左下角框中，称为查询变量。这将导致以下输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/e5a46cd3-5b66-4afe-90ae-fd607da0aa40.png)

为了能够从您的 React 应用程序中使用此变异，您需要对一些文件进行以下更改：

1.  在`client/src/constants.js`文件中创建一个新的导出常量，并将变异添加到其中：

```jsx
import gql from 'graphql-tag';

+ export const ADD_TO_CART = gql`
+  mutation addToCart($productId: Int!) {
+    addToCart(input: { productId: $productId }) {
+        total
+    }
+  }
+ `;

export const GET_CART_TOTAL = gql`
    ...
```

1.  目前，还没有按钮可以将产品添加到购物车，因此您可以在`Cart`目录中创建一个新文件，并将其命名为`AddToCartButton.js`。在这个文件中，您可以添加以下代码：

```jsx
import React from 'react'
import { Mutation } from 'react-apollo';
import Button from '../Button/Button';
import { ADD_TO_CART } from '../../constants';

const AddToCartButton = ({ productId }) => (
  <Mutation mutation={ADD_TO_CART}>
    {addToCart => (
      <Button onClick={() => addToCart({ variables: { productId }})}>
        {`+ Add to cart`}
      </Button>
    )}
  </Mutation>
);

export default AddToCartButton;
```

这个新的`AddToCartButton`将`productId`作为 prop，并且具有来自`react-apollo`的`Mutation`组件，该组件使用您在`client/src/constants.js`中创建的`Mutation`。`Mutation`的输出是调用此变异的实际函数，它以包含输入的对象作为参数。单击`Button`组件将执行变异。

1.  此按钮应显示在`Products`组件中列表中的产品旁边，其中每个产品都显示在`ProductItem`组件中。这意味着，您需要在`'src/components/Products/ProductItem.js'`中导入`AddCartButton`并通过以下代码传递`productId` prop 给它：

```jsx
import React from 'react';
import styled from 'styled-components';
+ import AddToCartButton from '../Cart/AddToCartButton';

...

const ProductItem = ({ data }) => (
  <ProductItemWrapper>
    <Thumbnail src={data.thumbnail} width={200} />
    <Title>{data.title}</Title>
+   <AddToCartButton productId={data.id} />
  </ProductItemWrapper>
);

export default ProductItem;
```

现在，当您在浏览器中打开 React 应用程序时，将会在产品标题旁边显示一个按钮。如果您点击此按钮，变更将被发送到 GraphQL 服务器，并且产品将被添加到购物车中。但是，您不会看到显示购物车（0）的按钮在`SubHeader`组件中的任何变化。

1.  要更新`CartButton`，您需要指定当购物车发生变更时，其他查询也应该再次执行。这可以通过在`client/src/components/Cart/AddToCartButton.js`中的`Mutation`组件上设置`refetchQueries`属性来完成。该属性接受一个包含有关应该请求的查询信息的对象数组。这些查询是由`CartButton`执行的`GET_CART_TOTAL`查询，以及`Cart`组件中的`GET_CART`查询。要做到这一点，请进行以下更改：

```jsx
import React from 'react'
import { Mutation } from 'react-apollo';
import Button from '../Button/Button';
- import { ADD_TO_CART, GET_CART_TOTAL } from '../../constants';
+ import { GET_CART, ADD_TO_CART, GET_CART_TOTAL } from '../../constants';

const AddToCartButton = ({ productId }) => (
-  <Mutation mutation={ADD_TO_CART}>
+  <Mutation mutation={ADD_TO_CART} refetchQueries={[{ query: GET_CART }, { query: GET_CART_TOTAL }]}>
    {addToCart => (
      <Button onClick={() => addToCart({ variables: { productId }})}>
        {`+ Add to cart`}
      </Button>
    )}
  </Mutation>
);

export default AddToCartButton;
```

现在，每当您从此组件向 GraphQL 服务器发送文档中的变更时，`GET_CART`和`GET_CART_TOTAL`查询也将被发送。如果结果发生了变化，`CartButton`和`Cart`组件将以新的输出进行渲染。

在这一部分，您已经添加了一些逻辑，通过使用 Apollo 的 GraphQL 客户端向 GraphQL 服务器发送查询和变更。这个客户端还有其他功能，比如本地状态管理，您将在下一部分学习到。

# 管理本地状态

您不仅可以使用 Apollo Client 来管理从 GraphQL 服务器获取的数据，还可以用它来管理本地状态。使用 Apollo，很容易将本地状态与从 GraphQL 服务器获取的数据结合起来，因为您还可以使用查询和变更来处理本地状态。

您可能希望将信息放入本地状态以便在这个电子商务商店中使用，比如应该从 GraphQL 服务器请求多少产品的数量。在本章的第一部分，您已经创建了一个带有名为`limit`的参数的查询，该参数定义了将返回多少产品。

要向应用程序添加本地状态，需要对 Apollo Client 的设置进行一些更改，之后还需要进行以下更改：

1.  在`client/src/App.js`文件中，您需要分离`cache`常量；这样，您就可以使用`writeData`方法向`cache`添加新值。此外，您还需要向`client`添加本地`resolvers`和`typeDefs`，这将在下一个`resolvers`和`typeDefs`之后使用 GraphQL 服务器。要做到这一点，更改以下代码：

```jsx
+ const cache = new InMemoryCache();

const client = new ApolloClient({
   link: new HttpLink({
     uri: 'http://localhost:4000/',
   }),
-  cache,
+  resolvers: {},
+  typeDefs: `
+    extend type Query {
+        limit: Int!
+    }
+  `,
});

+ cache.writeData({
+  data: {
+      limit: 5,
+  },
+ });
```

在上述代码块中，模式通过具有`limit`字段的`Query`类型进行了扩展，这意味着您可以查询`client`获取此值。此外，`limit`的初始值被写入了`cache`。这意味着当应用程序首次挂载时，`limit`的值将始终为`5`。

1.  让我们还将与产品相关的所有查询添加到`client/src/constants.js`文件中。这可以通过将以下代码添加到`client/src/components/Products`目录中的文件中来实现：

```jsx
import gql from 'graphql-tag';

...

+ export const GET_LIMIT = gql`
+  query getLimit {
+    limit @client
+  }
+ `;

+ export const GET_PRODUCTS = gql`
+  query getProducts {
+    products {
+      id
+      title
+      thumbnail
+    }
+  }
+ `;
```

1.  为了让`products`查询使用本地状态中的`limit`，必须对`GET_PRODUCTS`查询进行一些小改动：

```jsx
...

const GET_PRODUCTS = gql`
- query getProducts { + query getProducts($limit: Int) { -   products {
+   products(limit: $limit) {
      id
      title
      thumbnail
    }
  }
`;

export default GET_PRODUCTS;
```

这个`查询`现在将使用`limit`变量来请求产品的数量，而不是在 GraphQL 服务器中预定义的`10`值。通过添加`@client`，Apollo Client 将知道从`cache`获取这个值，意味着本地状态。

1.  在`Products`组件中，这些查询应该从`constants.js`文件中导入，并且应该使用`react-apollo`中的`Query`组件请求`limit`的值。此外，通过`Query`返回的`limit`值应在请求`GET_PRODUCTS`查询时发送到`variables`属性。因此，进行以下更改以使用更新后的查询并将变量传递给它：

```jsx
import React from 'react';
import styled from 'styled-components';
import {Query} from 'react-apollo';
- import gql from 'graphql-tag';
import SubHeader from '../Header/SubHeader';
import ProductItem from './ProductItem';
+ import { GET_PRODUCTS, GET_LIMIT } from '../../constants';

- const GET_PRODUCTS = gql`
- query getProducts {
-    products {
- id
- title
-       thumbnail
-    }
- }
- `;

...

const Products = ({ match, history }) => (
  <>
    {history && (
      <SubHeader title='Available products' goToCart={() => history.push('/cart')} />
    )}
    <Query query={GET_LIMIT}>
      {({ loading, error, data }) => (
-       <Query query={GET_PRODUCTS}>
+       <Query query={GET_PRODUCTS} variables={{ limit: parseInt(data.limit) }}>
          {({ loading, error, data }) => {
            if (loading || error) {
              return <Alert>{loading ? 'Loading...' : error}</Alert>;
            }
            return (
              <ProductItemsWrapper>
                {data.products && data.products.map(product => (
                  <ProductItem key={product.id} data={product} />
                ))}
              </ProductItemsWrapper>
            );
          }}
        </Query>
      )}
    </Query>
  </>
);

export default Products;
```

通过之前的更改，从`GET_LIMIT`查询返回的值将作为变量发送到`GET_PRODUCTS`查询，您需要确保使用`parseInt`将该值转换为整数。如果您现在在浏览器中查看应用程序，将显示 5 个产品。

1.  接下来，为了给`limit`设置一个初始值，这个值也可以动态设置。因此，您可以再次使用`writeData`方法来更新缓存。这应该从可以访问客户端的不同组件中完成。为了实现这一点，您需要在`client/src/components/Products`目录中的新的`Filter.js`文件中创建一个组件。在这个文件中，您可以放置以下代码：

```jsx
import React from 'react';
import { ApolloConsumer } from 'react-apollo';

const Filters = ({ limit }) => (
  <ApolloConsumer>
      {client => (
        <>
        <label for='limit'>Number of products: </label>
        <select id='limit' value={limit} onChange={e => client.writeData({ data: { limit: e.target.value } })}>
          <option value={5}>5</option>
          <option value={10}>10</option>
          <option value={20}>20</option>
        </select>
        </>
      )}
    </ApolloConsumer>
);

export default Filters;
```

这个`Filter`组件使用`ApolloConsumer`从`ApolloProvider`获取客户端的值，这类似于 React 上下文 API 的工作原理。从任何嵌套在`ApolloProvider`中的组件中，您都可以使用`react-apollo`中的 Consumer 来获取客户端值。客户端将用于向缓存写入数据，并且这些数据是从选择下拉菜单的值中检索出来的。

1.  `Filter`组件还应该添加到`Products`组件中，以便实际上可以用它来更改`limit`的值：

```jsx
import React from 'react';
import styled from 'styled-components';
import { Query } from 'react-apollo';
import SubHeader from '../Header/SubHeader';
import ProductItem from './ProductItem';
+ import Filters from './Filters';
import { GET_PRODUCTS, GET_LIMIT } from '../../constants';

...

const Products = ({ match, history }) => (
  <>
    {history && (
      <SubHeader title='Available products' goToCart={() => history.push('/cart')} />
    )}
    <Query query={GET_LIMIT}>
      {({ loading, error, data }) => (
+       <>
+         <Filters limit={parseInt(data.limit)} />
          <Query query={GET_PRODUCTS} variables={{ limit: parseInt(data.limit) }}>
            {({ loading, error, data }) => {
              if (loading || error) {
                return <Alert>{loading ? 'Loading...' : error}</Alert>;
              }
              return (
                <ProductItemsWrapper>
                  {data.products && data.products.map(product => (
                    <ProductItem key={product.id} data={product} />
                  ))}
                </ProductItemsWrapper>
              );
            }}
          </Query>
+       </>
      )}
    </Query>
  </>
);

export default Products;
```

由于`GET_PRODUCTS`的`Query`组件嵌套在`GET_LIMIT`的`Query`组件中，每当发送`GET_LIMIT`查询时，此查询也将被发送。因此，当您使用选择下拉菜单更改`limit`时，将发送`GET_PRODUCTS`查询，并且显示的产品数量将发生变化。

随着这些变化，您的应用程序将使用 Apollo Client 从 GraphQL 服务器获取数据并处理本地状态管理。此外，用户现在可以过滤在您的应用程序中看到的产品数量，这将使您的应用程序看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/dbb4a244-fbe1-4671-823c-1347303ead6e.png)

在上一节中添加了将产品添加到购物车的按钮，而购物车的功能将在下一节中处理，当您向项目添加身份验证时。

# 使用 React 和 GraphQL 进行身份验证

当用户将产品添加到购物车时，您希望他们能够结账，但在此之前，用户应该经过身份验证，因为您想知道谁在购买产品。在 React 中处理身份验证还需要与后端进行交互，因为您需要将用户信息存储在某个地方或检查用户是否存在。

在前端应用程序中进行身份验证时，大多数情况下会使用**JSON Web Tokens**（**JWTs**），这是加密令牌，可以轻松地用于与后端共享用户信息。当用户成功经过身份验证时，后端将返回 JWT，并且通常，此令牌将具有到期日期。用户应经过身份验证的每个请求都应发送令牌，以便后端服务器可以确定用户是否经过身份验证并且被允许执行此操作。尽管 JWT 可以用于身份验证，因为它们是加密的，但不应向其中添加私人信息，因为令牌只应用于对用户进行身份验证。只有在发送具有正确 JWT 的文档时，才可以从服务器发送私人信息。

# React Router 和身份验证

此项目的 GraphQL 服务器已经设置好处理身份验证，并且将在向其发送正确的用户信息时返回 JWT 令牌。当用户想要查看购物车时，应用程序将在本地或会话存储中查找 JWT 令牌，并将用户重定向到结账页面或登录页面。为此，应该在`react-router`中添加私人路由，只有在用户经过身份验证时才可用。

添加私人路由需要我们进行以下更改：

1.  在`client/src/components/App.js`文件的`Router`组件中必须添加新的结账和登录页面路由，用户可以在其中进行结账或登录。为此，您必须从`react-router-dom`中导入已经创建的`Checkout`和`Login`组件以及`Redirect`组件：

```jsx
import  React  from 'react'; import  styled, { createGlobalStyle } from 'styled-components'; - import { Route, Switch } from 'react-router-dom'**;**
**+ import { Route, Switch, Redirect } from 'react-router-dom';** import  Header  from './Header/Header'; import  Products  from './Products/Products'; import  Cart  from './Cart/Cart'; + import  Login  from './Checkout/Login'; + import  Checkout  from '**./Checkout/Checkout';**

...
```

1.  导入这些后，必须将路由添加到`Router`中的`Switch`，使其对用户可用：

```jsx
const  App  = () => (  <ApolloProvider  client={client}>
 <GlobalStyle  />
 <AppWrapper>
 <Header  />
 <Switch>
 <Route  exact  path='/'  component={Products}  /> <Route  path='/cart'  component={Cart}  /> +       <Route  path='/checkout'  component={Checkout}  /> +       <Route  path='/login/  component={Login} **/>** </Switch> </AppWrapper>
 </ApolloProvider> ); export  default  App;
```

1.  在当前情况下，用户可以在未经身份验证的情况下导航到`login`和`checkout`页面。要检查用户是否经过身份验证，可以使用`Route`组件的渲染属性方法。在这种方法中，您必须检查该用户的会话存储中是否存储了 JWT。目前，会话存储中没有存储令牌，因为这将在以后添加。但是您仍然可以通过添加以下函数来创建检查它的功能：

```jsx
...

**+ const** isAuthenticated  =  sessionStorage.getItem('token'**);** const  cache  =  new  InMemoryCache(); const  client  =  new  ApolloClient({

  ...
```

有许多存储 JWT 的方法，例如使用本地存储、会话存储、cookies 或者 `apollo-link-state` 包中的本地状态。只要遵循 JWT 的协议，在令牌中不加密私人信息，并为其添加到期日期，所有这些地方都可以被视为存储令牌的安全位置。

1.  之后，使用渲染 props 方法来检查结帐路由中用户是否经过身份验证。如果没有经过身份验证，用户将使用 `Redirect` 组件被重定向到登录页面。否则，用户将看到 `Checkout` 组件，该组件将接收由渲染 props 方法返回的路由 props。要实现这一点，请进行以下更改：

```jsx
const  App  = () => (  <ApolloProvider  client={client}>
 <GlobalStyle  />
 <AppWrapper>
 <Header  />
 <Switch>
 <Route  exact  path='/'  component={Products}  /> <Route  path='/cart'  component={Cart}  /> -       <Route  path='/checkout'  component={Checkout}  />
+       <Route 
+         path='/checkout' 
+         render={props => 
+           isAuthenticated() 
+             ? <Checkout /> 
+             : <Redirect to='/login' />
+         } 
+       />  <Route  path='/login'  component={Login}  /> </Switch>
    <AppWrapper>
 </ApolloProvider> ); export  default  App;
```

当您尝试访问浏览器中的 `http://localhost:3000/checkout` 路由时，您将始终被重定向到 `/login` 路由，因为会话存储中尚未存储 JWT。在本节的下一部分中，您将添加逻辑，通过发送带有登录信息的 mutation 来从 GraphQL 服务器检索 JWT。

# 从 GraphQL 服务器接收 JWT

GraphQL 服务器已经设置好处理身份验证，因为我们向其发送了包含带有我们的登录信息的 mutation 的文档。当您发送正确的用户名和密码时，服务器将返回一个包含您的用户名和到期日期的 JWT。可以通过使用 `react-apollo` 中的 `Mutation` 组件或使用提供更多灵活性的 React Apollo Hooks 来向 GraphQL 服务器发送查询。登录可以从 `Login` 组件中完成，您可以在 `client/src/components/Checkout/Login.js` 文件中找到该组件，在那里需要进行以下更改以对用户进行身份验证：

1.  用于 mutation 的 React Apollo Hook 需要一个将发送到 GraphQL 服务器的文档。这个 mutation 也可以在 `client/src/constants.js` 文件中定义，那里您也定义了所有其他查询和 mutation：

```jsx
import gql from 'graphql-tag';

... + export  const  LOGIN_USER  =  gql`
+   mutation loginUser($userName: String!, $password: String!) {
+     loginUser(userName: $userName, password: $password) {
+       userName
+       token
+     }
+   }
+ `;
```

1.  `client/src/components/Checkout/Login.js`中的`Login`组件已经在使用`useState` Hooks 来控制`userName`和`password`的输入字段的值。可以从`react-apollo`中导入`useMutation` Hook，并可以使用此 Hook 来替换`Mutation`组件并仍具有相同的功能。此 Hook 还可以从`ApolloProvider`中的任何位置使用，并返回一个登录函数，该函数将文档发送到 GraphQL 服务器。通过导入 Hook 并将`client/src/constants.js`中的`LOGIN_USER` mutation 传递给它来添加此操作：

```jsx
import  React  from 'react'; import  styled  from 'styled-components'; + import { useMutation } from 'react-apollo'; import  Button  from '../Button/Button'; + import { LOGIN_USER } from **'../../constants';**

... const  Login  = () => { + const [loginUser] =  useMutation(LOGIN_USER);   const [userName, setUserName] =  React.useState('');
  const [password, setPassword] =  React.useState('');

  return (

    ...
```

可以从`react-apollo`包中使用 React Apollo Hooks，但如果只想使用 Hooks，可以通过执行`npm install @apollo/react-hooks`安装`@apollo/react-hooks`来代替。GraphQL 组件，如`Query`或`Mutation`，在`react-apollo`和`@apollo/react-components`包中都可用。使用这些包将减少捆绑包的大小，因为您只导入所需的功能。

1.  创建`loginUser`函数后，可以将其添加到`Button`的`onClick`事件中，并将`userName`和`password`的值作为变量传递给此函数：

```jsx
return ( <LoginWrapper>
 <TextInput
 onChange={e  =>  setUserName(e.target.value)} value={userName} placeholder='Your username' /> <TextInput onChange={e  =>  setPassword(e.target.value)} value={password} placeholder='Your password' />
**-   <Button color='royalBlue'>**
**+** <Button
+ color='royalBlue'
+ onClick={() =>  loginUser({ variables: { userName, password } })}
+ **>**
 Login </Button>
 </LoginWrapper> );
```

1.  单击`Button`将发送包含`userName`和`password`值的文档到 GraphQL 服务器，如果成功，它将返回此用户的 JWT。但是，此令牌还应存储在会话存储中，并且由于`loginUser`函数返回一个 promise，`onClick`事件应该成为一个异步函数。这样，您可以等待`loginUser`函数解析并在之后存储令牌，或者如果没有返回令牌，则发送错误消息：

```jsx
...  <Button
 color='royalBlue'
**-** onClick={() =>  loginUser({ variables: { userName, password } })} + onClick={async () => { +   const { data } = await  loginUser({ +     variables: { userName, password } +   });
+ +   if (data.loginUser && data.loginUser.token) { +     sessionStorage.setItem('token', data.loginUser.token); +   } else { +     alert('Please provide (valid) authentication details'); +   } + }**}** >
 Login </Button> ...
```

1.  最后，如果身份验证成功，用户应该被重定向到“结账”页面。由于“登录”组件是通过渲染 props 方法由结账路由渲染的，它从`react-router`接收了 props。要将用户重定向回去，可以使用来自`react-router`的`history`props 将用户推到“结账”页面：

```jsx
...

- const Login = () => {
**+ const Login = ({ history }) => {**

  ...

  return (

    ...
 <Button
 color='royalBlue'
 onClick={async () => { ...        if (data.loginUser && data.loginUser.token) {
 sessionStorage.setItem('token', data.loginUser.token); +         return history.push('/checkout');        } else {
          alert('Please provide (valid) authentication details');
        }         
     ...

```

现在，只要会话存储中存储有令牌的用户就能访问“结账”页面。您可以通过转到浏览器的开发者工具中的应用程序选项卡，在那里，您会找到另一个名为会话存储的选项卡来从会话存储中删除令牌。

由于您希望用户能够从`cart`页面导航到`checkout`页面，您应该在`Cart`组件中添加一个`Button`，让用户可以使用`react-router-dom`中的`Link`组件进行导航。如果用户尚未经过身份验证，这将重定向用户到登录页面；否则，它将重定向他们到结账页面。此外，只有在购物车中有产品时才应显示该按钮。要添加此`Button`，需要在`client/src/components/Cart/Cart.js`中进行以下更改：

```jsx
import  React  from 'react'; import  styled  from 'styled-components'; import { Query } from 'react-apollo'; + import { Link } from 'react-router-dom'; import  SubHeader  from '../Header/SubHeader'; import  ProductItem  from '../Products/ProductItem'; + import  Button  from '../Button/Button'; import  Totals  from './Totals'; import { GET_CART } from '../../constants';

... const  Cart  = ({ history }) => (

  ... return (    <CartWrapper>
      <CartItemsWrapper>
        {data.cart && data.cart.products.map(product  => (          <ProductItem  key={product.id}  data={product}  />
        ))}
      </CartItemsWrapper>
      <Totals  count={data.cart.total}  />
**+** {data.cart && data.cart.products.length > 0 && (  +       <Link  to='/checkout'> +         <Button  color='royalBlue'>Checkout</Button> +       </Link**>
+     )}**
    </CartWrapper>
  );

  ...
```

您现在已经添加了继续应用程序的最终结账页面的功能，这使得在向其添加产品后，您的应用程序中的`/cart`路由如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/04e28956-c90e-4df3-a258-8f53df1cf079.png)

在本节的最后部分，您将向发送到 GraphQL 服务器的文档中添加这个令牌，该令牌将被验证以确保用户对某个操作进行了身份验证。

# 将 JWT 传递给 GraphQL 服务器

用户的身份验证细节以 JWT 的形式现在存储在会话存储中，结账页面的路由现在是私有的。但是为了让用户结账，这个令牌也应该被发送到 GraphQL 服务器，以及每个发送到服务器的文档，以验证用户是否真的被认证，或者令牌是否已经过期。因此，您需要扩展 Apollo Client 的设置，以便在向服务器发出请求时也发送令牌，并在前面加上`Bearer`，因为这是 JWT 的识别方式。

按照以下步骤将 JWT 传递给 GraphQL 服务器：

1.  您需要安装一个 Apollo 包来处理向上下文添加值，因为您需要`setContext`方法来做到这一点。这个方法可以从`apollo-link-Context`包中获得，您可以从`npm`安装：

```jsx
npm install apollo-link-Context
```

1.  Apollo Client 是在`client/src/components/App.js`文件中创建的，您可以从`apollo-link-Context`中导入`setContext`方法。此外，与 GraphQL 服务器的链接的创建必须解耦，因为这也应该带有身份验证细节，即`token`：

```jsx
...

import { ApolloClient } from 'apollo-client'; import { InMemoryCache } from 'apollo-cache-inmemory'; import { HttpLink } from 'apollo-link-http'; import { ApolloProvider } from 'react-apollo';
**+ import { setContext } from 'apollo-link-Context';** const  isAuthenticated  =  sessionStorage.getItem('token');

**+ const httpLink = new HttpLink({**
**+   uri: 'http://localhost:4000/graphql',**
**+ });** const  cache  =  new  InMemoryCache(); const  client  =  new  ApolloClient({
 link:  new  HttpLink({
 uri: 'http://localhost:4000/graphql',
 }), cache,
 resolvers: {

    ... 
```

1.  现在，您可以使用`setContext`方法来扩展发送到 GraphQL 服务器的请求头，以便它也包括可以从会话存储中检索到的令牌。您从会话存储中检索到的令牌必须以`Bearer`为前缀，因为 GraphQL 服务器期望以这种格式接收 JWT 令牌：

```jsx
... const  httpLink  =  new  HttpLink({
 uri: 'http://localhost:4000/graphql', }) + const  authLink  =  setContext((_, { headers }) => { +   const  token  =  isAuthenticated; +
+   return { +     headers: { +       ...headers, +       authorization:  token  ?  `Bearer ${token}`  : '',  +     }, +   }; **+ });** const  cache  =  new  InMemoryCache(); const  client  =  new  ApolloClient({

  ...
```

1.  与`HttpLink`方法一起，必须在设置 Apollo Client 时使用`authLink`常量；这将确保从`authLink`添加到由`httpLink`发送的标头的上下文值：

```jsx
...

const  client  =  new  ApolloClient({ - link:  new  HttpLink({ -   uri: 'http://localhost:4000/graphql', - }),
**+ l**ink:  authLink.concat(httpLink),  cache,
 resolvers: {

    ...
```

如果您再次在浏览器中访问应用程序，并确保已登录，方法是转到`checkout`或`login`页面，您会看到请求仍然发送到 GraphQL 服务器。当您打开浏览器的开发者工具并转到网络选项卡时，可以看到请求到服务器的标头信息不同。因为还发送了一个名为`authorization`的字段，其值看起来像 Bearer eyAABBB....

当用户转到结账页面时，应该有一个按钮来完成订单。此按钮将调用一个完成购物车的函数。由于用户必须经过身份验证才能创建订单，因此必须将令牌与发送`completeCart`变异的请求一起发送。此变异完成购物车并清除其内容，之后结账页面的内容会发生变化。

将此功能添加到`checkout`页面需要进行以下更改：

1.  `completeCart`变异具有以下形状，并且可以在`client/constants.js`中找到：

```jsx
export  const  COMPLETE_CART  =  gql`
 mutation completeCart { completeCart { complete } } `;
```

必须导入到`client/src/components/Checkout/Checkout.js`文件中：

```jsx
import  React  from 'react'; import  styled  from 'styled-components'; import  Button  from '../Button/Button'; + import { COMPLETE_CART } from '**../../constants';** 
... const  Checkout  = () => {
  ...
```

1.  可以使用从`react-apollo`导入的`useMutation` Hook 将变异发送到 GraphQL 服务器。在`Checkout`组件的开头，可以使用`COMPLETE_CART`变异作为参数添加 Hook。 Hook 返回发送变异的函数和从变异返回的数据：

```jsx
import  React  from 'react'; import  styled  from 'styled-components';
**+ import { useMutation } from 'react-apollo';** import  Button  from '../Button/Button'; import { COMPLETE_CART } from '../../constants';

... const  Checkout  = () => {
**+ [completeCart, { data }] = useMutation(COMPLETE_CART);**

  ...
```

1.  必须将`completeCart`函数添加到`Button`组件作为`onClick`属性，以便单击按钮时将调用该函数。此外，您必须检查`COMPLETE_CART`变异是否返回`complete`字段的值，该字段指示购物车是否已完成。如果是，则结账已完成，并且可以向用户显示不同的消息：

```jsx
...

const  Checkout  = () => {  const [completeCart, { data }] =  useMutation(COMPLETE_CART);
 return ( <CheckoutWrapper> +     {data && data.completeCart.complete ? ( +       <p>Completed checkout!</p> +     ) : ( **+       <>**
 <p>This is the checkout, press the button below to complete:</p> -         <Button  color='royalBlue'**>**
**+         <Button color='royalBlue' onClick={completeCart}>**
 Complete checkout </Button> +       </> +     )**}**
 </CheckoutWrapper>
 ); };

...
```

这结束了用户的结账流程和本章，您已经使用 React 和 GraphQL 创建了一个电子商务应用程序。

# 总结

在本章中，您已经创建了一个使用 GraphQL 作为后端的全栈 React 应用程序。使用 Apollo 服务器和模拟数据，创建了 GraphQL 服务器，该服务器接受查询和变异以提供数据。这个 GraphQL 服务器被一个使用 Apollo Client 的 React 应用程序使用，用于向服务器发送和接收数据以及处理本地状态管理。身份验证由 GraphQL 服务器使用 JWT 处理，在前端由 React 和`react-router`处理。

就是这样！您已经完成了本书的第七章，并且已经使用 React 创建了七个 Web 应用程序。到目前为止，您应该对 React 及其功能感到满意，并准备学习更多。在下一章中，您将介绍 React Native，并学习如何使用 React 技能来创建一个移动应用程序，通过使用 React Native 和 Expo 创建一个房源列表应用程序。

# 进一步阅读

+   从头开始创建 Apollo 服务器：[`www.apollographql.com/docs/apollo-server/essentials/server`](https://www.apollographql.com/docs/apollo-server/essentials/server)

+   GraphQL：[`graphql.org/learn/`](https://graphql.org/learn/)

+   JWT 令牌：[`jwt.io/introduction/`](https://jwt.io/introduction/)


# 第八章：使用 React Native 和 Expo 构建房屋列表应用程序

React 开发的一个标语是*学一次，随处编写*，这是由于 React Native 的存在。使用 React Native，您可以使用 JavaScript 和 React 编写原生移动应用程序，同时使用 React 的相同功能，例如状态管理。在本书中已经获取的 React 知识的基础上，您将从本章开始探索 React Native。由于 React 和 React Native 有很多相似之处，建议您在对 React 知识感到不安时再次查看一些以前的章节。

在本章中，您将使用 React Native 创建一个移动应用程序，该应用程序使用了您在之前章节中看到的相同语法和模式。您将设置基本路由，探索 iOS 和 Android 开发之间的差异，并学习如何使用`styled-components`对 React Native 组件进行样式设置。此外，将使用名为**Expo**的工具链来运行和部署您的 React Native 应用程序。

本章将涵盖以下主题：

+   创建 React Native 项目

+   移动应用程序的路由

+   React Native 中的生命周期

+   在 React Native 中设置组件样式

# 项目概述

在本章中，我们将创建一个房屋列表应用程序，显示可用房屋的概述，并使用`styled-components`进行样式设置和**React Navigation**进行路由。数据是从模拟 API 中获取的。

构建时间为 1.5 小时。

# 入门

确保您已在 iOS 或 Android 设备上安装了 Expo 客户端应用程序，以便能够运行您在本章中创建的应用程序。Expo 客户端可在 Apple 应用商店和 Google Play 商店中下载。

一旦您下载了应用程序，您需要创建一个 Expo 账户，以使开发过程更加顺利。确保将您的账户详细信息存储在安全的地方，因为您稍后在本章中会需要这些信息。**不要忘记通过点击您收到的电子邮件中的链接来验证您的电子邮件地址。**

本章的完整代码可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch8`](https://github.com/PacktPublishing/React-Projects/tree/ch8)[.](https://github.com/PacktPublishing/React-Projects/tree/ch7)

此应用程序是使用 Expo SDK 版本 33.0.0 创建的，因此您需要确保您在本地计算机上使用的 Expo 版本相似。由于 React Native 和 Expo 经常更新，请确保您使用此版本，以确保本章描述的模式表现如预期。如果您的应用程序无法启动或收到错误消息，请务必查看 Expo 文档，以了解有关更新 Expo SDK 的更多信息。

# 使用 React Native 和 Expo 构建房源列表应用程序

在本节中，您将使用 React Native 和 Expo 构建一个房源列表应用程序，这使您可以使用与 React 相同的语法和模式，因为它使用了 React 库。此外，Expo 使得无需安装和配置 Xcode（用于 iOS）或 Android Studio 即可开始在您的计算机上创建原生应用程序成为可能。因此，您可以从任何计算机上为 iOS 和 Android 平台编写应用程序。

您还可以使用 Expo web 在浏览器中运行 React Native 应用程序，以创建渐进式 Web 应用程序（PWA）。但是，同时为 iOS、Android 和 Web 开发仍处于实验阶段，可能需要大量性能和架构修复。此外，并非所有在移动设备上的 React Native 中工作的包也会在 Expo web 上工作。

Expo 将 React API 和 JavaScript API 与 React Native 开发流程结合在一起，以便允许诸如 JSX 组件、Hooks 和原生功能（如相机访问）等功能。大致上，Expo 工具链由多个工具组成，这些工具可以帮助您进行 React Native 开发，例如 Expo CLI，它允许您从终端创建 React Native 项目，并提供运行 React Native 所需的所有依赖项。使用 Expo 客户端，您可以从连接到本地网络的 iOS 和 Android 移动设备上打开这些项目。Expo SDK 是一个包，其中包含了使您的应用能够在多个设备和平台上运行的所有库。

# 创建 React Native 项目

在本书中，每个新的 React 项目的起点都是使用 Create React App 为您的应用程序创建一个样板。对于 React Native，有一个类似的样板可用，它是 Expo CLI 的一部分，并且可以像这样轻松设置：

您需要使用以下命令使用`npm`全局安装 Expo CLI：

```jsx
npm install -g expo-cli
```

这将启动安装过程，这可能需要一些时间，因为它将安装帮助您开发移动应用程序的所有依赖项的 Expo CLI。之后，您可以使用 Expo CLI 的`init`命令创建新项目：

```jsx
expo init house-listing
```

Expo 现在将为您创建项目，但首先会要求您回答以下问题：

1.  它会询问您是否要创建一个空白模板，带有 TypeScript 配置的空白模板，或者带有一些示例屏幕设置的示例模板。在本章中，您需要选择第一个选项：空白（`expo-template-blank`）。

1.  选择模板后，您需要输入应用程序的名称，在这种情况下是房源列表。此名称将添加到`app.json`文件中，其中包含有关您的应用程序的配置信息。

1.  Expo 会自动检测您的计算机上是否安装了 Yarn。如果安装了 Yarn，它将要求您使用 Yarn 安装其他必要的依赖项来设置您的计算机。如果安装了 Yarn，请选择“是”；否则，默认情况下将使用 npm。在本章中，建议使用 npm 而不是 Yarn，以便与之前的章节保持一致。

现在，您的应用程序将使用您选择的设置创建。可以通过以下命令进入 Expo 刚刚创建的目录来启动此应用程序：

```jsx
cd house-listing
npm start
```

这将启动 Expo，并使您能够从终端或浏览器启动项目，从而可以在移动设备上运行应用程序，或者使用 iOS 或 Android 模拟器。在终端中，有多种方法可以打开应用程序：

+   使用 Android 或 iOS 上 Expo Client 的用户名登录。您的项目将自动显示在移动设备的“项目”选项卡中。

+   使用运行在 Android 或 iOS 上的移动设备扫描显示的 QR 码。如果您使用的是 Android 设备，可以直接从 Expo Client 应用程序扫描 QR 码。在 iOS 上，您需要使用相机扫描该代码，然后会要求您打开 Expo Client。

+   按下`a`键打开 Android 模拟器，或按下`i`键打开 iOS 模拟器。请记住，您需要安装 Xcode 和/或 Android Studio 才能使用其中一个模拟器。

+   通过按下`e`键将链接发送到您的电子邮件，这个链接可以从安装有 Expo Client 应用程序的移动设备上打开。

另外，运行`npm start`命令会在`http://localhost:19002/`URL 上打开你的浏览器，显示 Expo 开发者工具。这个页面看起来会像这样，假设你安装了在*入门*部分提到的 Expo SDK 的版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/6a61b79f-7752-49fc-897c-ad7f75cba8ae.png)

在这个页面上，你可以看到左边有一个侧边栏，右边是你的 React Native 应用的日志。这个侧边栏包含按钮，让你可以启动 iOS 或 Android 模拟器，你需要安装 Xcode 或 Android Studio。另外，你也可以找到一个按钮，通过邮件发送一个链接或者使用之前安装的 Expo 应用在你的移动设备上生成一个 QR 码来打开应用。

在这一点上，你的应用应该看起来如下。这个截图是从一个 iOS 设备上拍摄的。无论你是使用 iOS 或 Android 模拟器打开应用，还是从 iOS 或 Android 设备上打开应用，都不应该有影响：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/5f4e5ce7-020e-42af-9b8e-bf29cf94ba4a.png)

这个应用是使用**Expo SDK 版本 33.0.0**创建的，所以你需要确保你本地机器上使用的 Expo 版本是相似的。由于 React Native 和 Expo 经常更新，确保你使用这个版本来确保本章描述的模式表现如预期。如果你的应用无法启动或者收到错误，确保查看 Expo 文档以了解更多关于更新 Expo SDK 的信息。

这个 React Native 应用的项目结构与我们之前在前几章创建的 React 项目非常相似，我们是用 Expo 创建的。它看起来如下：

```jsx
house-listing
|-- .expo
|-- assets
    |-- icon.png
    |-- splash.png
|-- node_modules
.gitignore
App.js
app.json
babel.config.js
package.json
```

在`assets`目录中，你可以找到用于应用主屏幕图标的图片，一旦你在移动设备上安装了这个应用，以及用作启动画面的图片，当你启动应用时会显示。`App.js`文件是你应用的实际入口点，在这里你会返回当应用挂载时将被渲染的组件。应用的配置，例如 App Store 的配置，被放置在`app.json`中，而`babel.config.js`包含特定的 Babel 配置。

# 在 React Native 中设置路由

正如我们之前提到的，`App.js`文件是您的应用程序的入口点，由 Expo 定义。如果您打开这个文件，您会看到它由组件组成，并且`StyleSheet`直接从`react-native`导入。在 React Native 中编写样式的语法与在浏览器中使用的 React 不同，因此您将不得不在本章后面安装`styled-components`。

# 使用 React Navigation 创建路由

让我们继续安装 React Navigation。在 React Native 中有许多可用的包来帮助您处理路由，但这是 Expo 推荐使用的最受欢迎的包之一。除了 React Navigation，您还必须安装相关的包，称为`react-navigation-stack`和`react-navigation-tabs`，这些包需要为您的应用程序创建导航器。可以通过运行以下命令来安装 React Navigation 及其依赖项：

```jsx
npm install react-navigation react-navigation-stack react-navigation-tabs
```

要向您的 React Native 应用程序添加路由，您需要了解在浏览器和移动应用程序中的路由之间的区别。在 React Native 中，历史记录的行为方式与在浏览器中不同，在浏览器中，用户可以通过更改浏览器中的 URL 导航到不同的页面，并且先前访问的 URL 将被添加到浏览器历史记录中。相反，您需要自己跟踪页面之间的转换并在应用程序中存储本地历史记录。

使用 React Navigation，您可以使用多个不同的导航器来帮助您实现这一点，包括堆栈导航器和选项卡导航器。堆栈导航器的行为方式与浏览器非常相似，因为它在页面之间进行转换后堆叠页面，并允许您使用 iOS 和 Android 的本机手势和动画进行导航：

1.  您可以通过将包含路由配置的对象传递给`createStackNavigator`方法来设置堆栈导航器，该方法可以从`react-navigation-stack`在`App.js`文件中导入。此外，您还需要从`react-navigation`导入`createAppContainer`，它可以帮助您返回一个包装所有路由的组件：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
+ import { createAppContainer } from 'react-navigation';
+ import { createStackNavigator } from 'react-navigation-stack';

export default function App() {
    ...
```

1.  您需要返回使用`createStackNavigator`创建的组件，而不是返回一个名为`App`的组件，该组件保存了应用程序的所有路由。这个`StackNavigator`组件需要使用`createAppContainer`导出，如下所示：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';

- export default function App() {
- return (
+ const Home = () => (
    <View style={styles.container}>
        <Text>Open up App.js to start working on your app!</Text>
    </View>
  );
- } const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
}); + const StackNavigator = createStackNavigator({
+  Home: {
+    screen: Home,
+  },
+ });

+ export default createAppContainer(StackNavigator);
```

1.  您的应用程序现在有一个名为`Home`的路由，并呈现`Home`组件。您还可以通过在传递给`createStackNavigator`的对象中设置`navigationOptions`字段来为此屏幕添加`title`，如下所示：

```jsx
...

const AppNavigator = createStackNavigator({
  Home: {
    screen: Home,
+   navigationOptions: { title: 'Home' },
  },
});

export default createAppContainer(AppNavigator);
```

1.  要创建另一个路由，您可以通过添加`Detail`组件并添加呈现此组件的路由来复制此过程：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';

const Home = () => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
  </View>
);

+ const Detail = () => (
+  <View style={styles.container}>
+    <Text>Open up App.js to start working on your app!</Text>
+  </View>
+ );

...

const AppNavigator = createStackNavigator({
  Home: {
    screen: Home,
    navigationOptions: { title: 'Home' },
  },
+ Detail: {
+   screen: Detail,
+   navigationOptions: { title: 'Detail' },
+ },
});

export default createAppContainer(AppNavigator);
```

1.  现在您的应用程序中有两个屏幕，您还需要设置一个默认路由，该路由在应用程序首次挂载时将呈现。您可以通过使用以下代码扩展传递给`createStackNavigator`的路由配置对象来执行此操作：

```jsx
...

const AppNavigator = createStackNavigator({
  Home: {
    screen: Home,
    navigationOptions: { title: 'Home' },
  },
  Detail: {
    screen: Detail,
    navigationOptions: { title: 'Detail' },
  },
+ }, { initialRouteName: 'Home' });
- });

export default createAppContainer(AppNavigator);
```

您可以通过将`initialRouteName`的值更改为`Detail`，并检查应用程序中呈现的屏幕是否具有标题`Detail`，来看到`Detail`路由也正在呈现。

在本节的下一部分中，您将学习如何在此导航器创建的不同屏幕之间进行过渡。

# 在屏幕之间过渡

在 React Native 中，在屏幕之间过渡也与在浏览器中有些不同，因为再次，没有 URL。相反，您需要使用`navigation`属性，该属性可从堆栈导航器呈现的组件中获取。`navigation`属性可用于通过进行以下更改来处理路由：

1.  您可以从`Home`和`Detail`组件中访问此示例中的`navigation`属性：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';

- const Home = () => (
+ const Home = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
  </View>
);

...
```

1.  `navigation`属性包含多个值，包括`navigate`函数，该函数以路由名称作为参数。您可以将此函数用作事件，例如，您可以从`react-native`导入的`Button`组件上调用`onPress`事件处理程序来单击按钮。与您在 React 中习惯的方式相比，您可以通过调用`onPress`事件处理程序而不是`onClick`来单击按钮。此外，`Button`组件不接受子元素作为属性，而是接受`title`属性。要做到这一点，请更改以下代码：

```jsx
import React from 'react';
- import { StyleSheet, Text, View } from 'react-native';
+ import { Button, StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';

const Home = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
+   <Button onPress={() => navigation.navigate('Detail')} title='Go to Detail' />
  </View>
);

...
```

1.  当您按下标题为`转到详细信息`的按钮时，您将转到`Detail`屏幕。此屏幕的标题栏还将呈现一个`返回`按钮，当您按下它时，将返回到`Home`屏幕。您还可以使用`navigation`属性中的`goBack`函数创建自定义返回按钮，如下所示：

```jsx
...

- const Detail = () => (
+ const Detail = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
+    <Button onPress={() => navigation.goBack()} title='Go to back to Home' />
  </View>
);

...
```

通常，将这些组件存储在不同的目录中，并且只使用`App.js`文件可以使您的应用程序更易读。为了实现这一点，您需要在应用程序的根目录中创建一个名为`Screens`的新目录，在其中需要为您刚刚创建的两个屏幕中的每一个添加一个文件。让我们学习如何做到这一点：

1.  在`Screens`目录中创建一个名为`Home.js`的文件，并将`Home`组件添加到该文件中，包括所使用模块的导入。`Home`组件的代码如下：

```jsx
import React from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';

const Home = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
    <Button onPress={() => navigation.navigate('Detail')} title='Go to Detail' />
  </View>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});

export default Home;
```

1.  您需要为`Detail`屏幕做同样的事情，方法是创建`Screens/Detail.js`文件，并将`Detail`组件和所使用的模块的代码添加到该文件中。您可以通过向该新文件添加以下代码块来实现这一点：

```jsx
import React from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';

const Detail = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
    <Button onPress={() => navigation.goBack()} title='Go to back to Home' />
  </View>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});

export default Detail;
```

1.  在`App.js`文件中，您需要导入`Home`和`Detail`组件，并删除先前创建这两个组件的代码块，如下所示：

```jsx
import React from 'react';
- import { Button, StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack'; + import Home from './Screens/Home';
+ import Detail from './Screens/Detail';

- const Home = ({ navigation }) => (
-   <View style={styles.container}>
-     <Text>Open up App.js to start working on your app!</Text>
-     <Button onPress={() => navigation.navigate('Detail')} title='Go to Detail' />
-   </View>
- );

- const Detail = ({ navigation }) => (
-   <View style={styles.container}>
-     <Text>Open up App.js to start working on your app!</Text>
-     <Button onPress={() => navigation.goBack()} title='Go to back to Home' />
-   </View>
- );

- const styles = StyleSheet.create({
-  container: {
-   flex: 1,
-   backgroundColor: '#fff',
-   alignItems: 'center',
-   justifyContent: 'center',
-  },
- });

const AppNavigator = createStackNavigator({
  Home: {
    screen: Home,
    navigationOptions: { title: 'Home' },
  },
  Detail: {
    screen: Detail,
    navigationOptions: { title: 'Detail' },
  },
}, { initialRouteName: 'Home' });

export default createAppContainer(AppNavigator);
```

您的应用程序只使用`App.js`文件来创建路由并设置堆栈导航器。许多应用程序在彼此旁边使用多种类型的导航器，这将在本节的下一部分中展示。

# 将多个导航器一起使用

对于更复杂的应用程序，您不希望所有的路由都堆叠在一起；您只希望为彼此相关的路由创建这些堆栈。幸运的是，您可以在 React Navigation 中同时使用不同类型的导航器。可以通过以下方式使用多个导航器来完成应用程序：

1.  在移动应用程序中导航的最常见方式之一是使用选项卡；React Navigation 也可以为您创建选项卡导航器。因此，您需要将一个路由对象传递给`createBottomTabNavigator`方法，您可以使用以下代码从`react-navigation-tabs`导入它：

```jsx
import React from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
+ import { createBottomTabNavigator } from 'react-navigation-tabs'; 
import Home from './Screens/Home';
import Detail from './Screens/Detail';

...
```

1.  假设您希望“主页”屏幕和相邻的“详细”屏幕在同一个选项卡上可用-您需要为这些屏幕重命名堆栈导航器。这个堆栈导航器应该被添加到传递给`createBottomTabNavigator`的路由对象中，该对象创建了选项卡导航器。加载的初始路由声明现在也与选项卡导航器相关联：

```jsx
import React from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation'; 
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';
import Home from './Screens/Home';
import Detail from './Screens/Detail';

- const AppNavigator = createStackNavigator({
+ const HomeStack = createStackNavigator({
    Home: {
      screen: Home,
      navigationOptions: { title: 'Home' },
    },
    Detail: {
      screen: Detail,
      navigationOptions: { title: 'Detail' },
    },
-  }, { initialRouteName: 'Home' });
+ });

+ const AppNavigator = createBottomTabNavigator({
+  Home: HomeStack
+ }, { initialRouteName: 'Home' });

export default createAppContainer(AppNavigator);
```

您应用程序的主要导航现在是选项卡导航器，只有一个名为`Home`的选项卡。此选项卡将呈现包含`Home`和`Detail`路由的堆栈导航器，这意味着您仍然可以在不离开`Home`选项卡的情况下导航到`Detail`屏幕。

1.  您可以轻松地向选项卡导航器添加另一个选项卡，该选项卡将呈现组件或另一个堆栈导航器。让我们创建一个名为`Settings`的新屏幕，首先需要在`Screens/Settings.js`文件中创建一个新组件：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

const Settings = ({ navigation }) => (
  <View style={styles.container}>
    <Text>Open up App.js to start working on your app!</Text>
  </View>
);

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});

export default Settings;
```

1.  在`App.js`中导入此组件，以将新的`Screens`路由添加到选项卡导航器。在您进行这些更改后，此屏幕将呈现`Settings`组件：

```jsx
import React from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';
import Home from './Screens/Home';
import Detail from './Screens/Detail';
+ import Settings from './Screens/Settings';

...

const AppNavigator = createBottomTabNavigator({
   Home: HomeStack,
+  Settings,
}, { initialRouteName: 'Home' });

export default createAppContainer(AppNavigator);
```

1.  您的应用程序现在有一个名为`Settings`的选项卡，它将呈现`Settings`组件。但是，例如此屏幕的`title`是不可能自定义的。因此，您需要使用以下代码创建另一个只有`Settings`路由的堆栈导航器：

```jsx
...

+ const SettingsStack = createStackNavigator({
+  Settings: {
+    screen: Settings,
+    navigationOptions: { title: 'Settings' },
+  },
+ });

const AppNavigator = createBottomTabNavigator({
   Home: HomeStack,
-  Settings,
+  Settings: SettingsStack,
}, { initialRouteName: 'Home' });

export default createAppContainer(AppNavigator);
```

您现在已经在应用程序中添加了堆栈导航器和选项卡导航器，这使您可以同时在屏幕和选项卡之间导航。如果您正在使用 iOS 模拟器或运行 iOS 的设备上运行应用程序，它将看起来完全像以下屏幕截图。对于 Android，在这一点上，应用程序应该看起来非常相似：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/5a45f6bb-5a7a-4303-a513-1b6b9a2b3586.png)

在下一节中，您将从模拟 API 加载数据，并使用 React 生命周期在不同的屏幕中加载这些数据。

# 在 React Native 中使用生命周期

在开始为 React Native 组件添加样式之前，您需要在应用程序中获取一些数据，这些数据将由这些组件显示。因此，您需要使用生命周期来检索这些数据并将其添加到应用程序的本地状态中。

要获取数据，您将再次使用`fetch` API，并结合`useState`和`useEffect` Hooks 在生命周期内检索这些数据。一旦从模拟 API 中获取了数据，它可以在 React Native 的`FlatList`组件中显示。可以通过以下方式使用 Hooks 向 React Native 应用程序添加生命周期方法：

1.  您将使用`useState` Hook 来设置加载指示器、错误消息和显示数据的常量，其中`loading`常量应最初为 true，`error`常量应为空，`data`常量应为空数组：

```jsx
...

- const Home = ({ navigation }) => (
+ const Home = ({ navigation }) => {
+  const [loading, setLoading] = React.useState(true);
+  const [error, setError] = React.useState('');
+  const [data, setData] = React.useState([]);

+  return (
    <View style={styles.container}>
      <Text>Open up App.js to start working on your app!</Text>
      <Button onPress={() => navigation.navigate('Detail')} title='Go to Detail' />
    </View>
   )
+ };
```

1.  接下来，您需要创建一个异步函数，从模拟 API 中检索数据，并从应用程序挂载时调用`useEffect` Hook。当 API 请求成功时，`fetchAPI`函数将更改`loading`、`error`和`data`的两个常量。如果不成功，错误消息将被添加到`error`常量中。

```jsx
...
const Home = ({ navigation }) => {
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState('');
  const [data, setData] = React.useState([]);

+  const fetchAPI = async () => {
+    try {
+      const data = await fetch('https://my-json-server.typicode.com/PacktPublishing/React-Projects/listings');
+      const dataJSON = await data.json();

+      if (dataJSON) {
+        setData(dataJSON);
+        setLoading(false);
+      }
+    } catch(error) {
+      setLoading(false);
+      setError(error.message);
+    }
+  };

+  React.useEffect(() => {
+    fetchAPI();
+  }, []);

  return (
    ...
```

1.  现在，这个数据常量可以作为`FlatList`组件的一个 prop 添加，它会遍历数据并渲染显示这些数据的组件。`FlatList`返回一个包含名为`item`的字段的对象，其中包含每次迭代的数据，如下所示：

```jsx
import React from 'react';
- import { Button, StyleSheet, Text, View } from 'react-native';
+ import { FlatList, StyleSheet, Text, View } from 'react-native';

const Home = ({ navigation }) => {

  ...

  return (
    <View style={styles.container}>
-     <Text>Open up App.js to start working on your app!</Text>
-     <Button onPress={() => navigation.navigate('Detail')} title='Go to Detail' />
+     {!loading && !error && <FlatList
+       data={data}
+       renderItem={({item}) => <Text>{item.title}</Text>}
+     />}
    </View>
  )
};

...
```

1.  就像我们在 React 中可以做的那样，当使用`map`或`forEach`函数时，您需要在每个迭代的组件上指定一个`key`属性。`FlatList`会自动查找`data`对象中的`key`字段，但如果您没有特定的`key`字段，您需要使用`keyExtractor`属性来设置它。重要的是要知道，用于键的值应该是一个字符串，因此您需要将模拟 API 返回的`id`字段转换为字符串：

```jsx
  ...

  return (
    <View style={styles.container}>
     {!loading && !error && <FlatList
       data={data}
+      keyExtractor={item => String(item.id)}
       renderItem={({item}) => <Text>{item.title}</Text>}
     />}
    </View>
  );
};

...
```

现在，您的应用程序将显示来自模拟 API 的房源标题列表，而无需路由到特定的列表或样式。这将使您的应用程序看起来如下，Android 和 iOS 之间的差异应该是有限的，因为我们尚未向应用程序添加任何重要的样式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/841776ec-33b6-4991-8327-ba35ae187dab.png)

要再次将导航添加到`Detail`路由，您需要从`FlatList`返回一个支持`onPress`事件的组件。例如，您之前使用的`Button`组件和`TouchableOpacity`组件。这个最后一个组件可以用作`View`组件的替代品，它不支持`onPress`事件。在这里创建导航是通过进行以下更改完成的：

1.  您需要从`react-native`中导入`TouchableOpacity`组件，并用这个组件包装`FlatList`返回的`Text`组件。`onPress`事件将从`navigation`属性调用`navigate`函数，并导航到`Detail`路由，如果我们更改以下代码：

```jsx
import React from 'react';
- import { FlatList, View, Text } from 'react-native';
+ import { FlatList, View, Text, TouchableOpacity } from 'react-native';

const Home = ({ navigation }) => {
  ...

  return (
    <View style={styles.container>
      {!loading && !error && <FlatList
        data={data}
        keyExtractor={item => String(item.id)}
-       renderItem={({item}) => <Text>{item.text}</Text>}
+       renderItem={({item}) => (
+         <TouchableOpacity onPress={() => navigation.navigate('Detail')}>
+           <Text>{item.title}</Text>
+         </TouchableOpacity>
+       )}
      />}
    </View>
  );
};

...
```

1.  当您单击应用程序中显示的任何标题时，您将导航到“详细”路由。但是，您希望此屏幕显示您刚刚按下的项目。因此，一旦按下`TouchableOpacity`组件，您将需要向此路由传递参数。为此，您需要将这些参数作为对象传递给`navigate`函数：

```jsx
  ...

  return (
    <View style={styles.container>
      {!loading && !error && <FlatList
        data={data}
        keyExtractor={item => String(item.id)}
        renderItem={({item}) => (
-         <TouchableOpacity onPress={() => navigation.navigate('Detail')}>
+         <TouchableOpacity onPress={() => navigation.navigate('Detail', { item })}>
           <Text>{item.title}</Text>
         </TouchableOpacity>
       )}
      />}
    </View>
  );
};

...
```

1.  从由“详细”路由呈现的组件中，您可以从`navigation`属性中获取此参数对象，并使用它来显示该项目。要从`navigation`属性获取参数，您可以使用`getParam`函数，其中您需要指定要获取的参数的名称和此参数的回退值。就像我们为“主页”路由所做的那样，您可以显示列表的`title`，在这种情况下应该是来自`item`参数的`title`：

```jsx
import React from 'react';
- import { Button, StyleSheet, Text, View } from 'react-native';
+ import { StyleSheet, Text, View } from 'react-native';

- const Detail = ({ navigation }) => (
+ const Detail = ({ navigation }) => {
+   const item = navigation.getParam('item', {})

+   return (
      <View style={styles.container}>
-       <Text>Open up - App.js to start working on your app!</Text>
-       <Button onPress={() => navigation.goBack()} title='Go to back to Home' />
+       <Text>{item.title}</Text>
      </View>
    );
+ };

...

export default Detail;
```

不要传递包含所点击项目数据的整个对象，而是只需发送项目的 ID。这样，您可以获取模拟 API 以获取此列表的数据，并在“详细”路由上显示它。要获取单个列表，您需要发送请求到`'listings/:id'`路由。

您现在可以查看来自模拟 API 的所有列表和来自此 API 的特定列表。下一节将使用`styled-components`添加样式。

# 样式化 React Native 应用程序

到目前为止，在此应用程序中用于样式化 React Native 组件的语法看起来与您已经使用的有些不同。因此，您可以安装`styled-components`以使用您已经熟悉的样式编写语法。要安装此内容，您需要运行以下命令：

```jsx
npm install styled-components
```

这将安装`styled-components`包，之后您可以继续为应用程序中已经存在的组件创建样式：

1.  让我们从将`Screens/Home.js`文件中的`View`和`FlatList`组件转换为`styled-components`开始。为此，您需要从`styled-components/native`中导入`styled`，因为您只想导入包的特定本机部分：

```jsx
import React from 'react';
- import { FlatList, StyleSheet, Text, View, TouchableOpacity } from 'react-native';
+ import { FlatList, Text, View, TouchableOpacity } from 'react-native';
+ import styled from 'styled-components/native'; 
const Home = ({ navigation }) => {
  ...
```

1.  文件底部的`StyleSheet`创建了`View`组件的样式，应该将其转换为使用`styled-components`样式的组件。正如我们在前几章中看到的那样，您也可以扩展现有组件的样式。大多数样式规则可以复制并更改为`styled-components`的语法，如下代码块所示：

```jsx
... + const ListingsWrapper = styled(View)`
+  flex: 1;
+  background-color: #fff;
+  align-items: center;
+  justify-content: center;
+ `

- const styles = StyleSheet.create({
-   container: {
-     flex: 1,
-     backgroundColor: '#fff',
-     alignItems: 'center',
-     justifyContent: 'center',
-   },
- }); 
const Home = ({ navigation }) => {
  ...
  return (
-    <View style={styles.container}>
+    <ListingsWrapper>
      {!loading && !error && <FlatList
        data={data}
        keyExtractor={item => String(item.id)}
        renderItem={({item}) => (
          <TouchableOpacity onPress={() => navigation.navigate('Detail', { item })}>
            <Text>{item.title}</Text>
          </TouchableOpacity>
        )}
      />}
+    </ListingsWrapper>
-    </View>
  );
};

export default Home;
```

1.  `FlatList`组件也可以做同样的事情，即通过使用`styled-components`中的`styled`来扩展此组件的样式，并设置自定义样式规则，如下所示：

```jsx
...

const ListingsWrapper = styled(View)`
  flex: 1;
  background-color: #fff;
  align-items: center;
  justify-content: center;
`

+ const Listings = styled(FlatList)`
+  width: 100%;
+  padding: 5%;
+ `; 
const Home = ({ navigation }) => {
  ...
  return (
    <ListingsWrapper>
-     {!loading && !error && <FlatList
+     {!loading && !error && <Listings
        data={data}
        keyExtractor={item => String(item.id)}
        renderItem={({item}) => (
          <TouchableOpacity onPress={() => navigation.navigate('Detail', { item })}>
            <Text>{item.title}</Text>
          </TouchableOpacity>
        )}
      />}
    </ListingsWrapper>
  );
};

export default Home;
```

1.  `FlatList`目前只返回一个带有`title`的`Text`组件，而可以显示更多数据。为了做到这一点，您需要创建一个新的组件，该组件返回包含来自模拟 API 的列表数据的多个组件。您可以在一个名为`Components`的新目录中完成这个操作，该目录包含另一个名为`Listing`的目录。在这个目录中，您需要创建`ListingItem.js`文件，并将以下代码块放入其中：

```jsx
import React from 'react';
import styled from 'styled-components/native';
import { Image, Text, View, TouchableOpacity } from 'react-native';

const ListingItemWrapper = styled(TouchableOpacity)`
 display: flex;
 flex-direction: row;
 padding: 2%;
 background-color: #eee;
 border-radius: 5px;
 margin-bottom: 5%;
`;

export const Title = styled(Text)`
 flex-wrap: wrap;
 width: 99%;
 font-size: 20px;
`

export const Price = styled(Text)`
 font-weight: bold;
 font-size: 20px;
 color: blue;
`

const Thumbnail = styled(Image)`
 border-radius: 5px;
 margin-right: 4%;
 height: 200px;
 width: 200px;
`

const ListingItem = ({ item, navigation }) => (
 <ListingItemWrapper onPress={() => navigation.navigate('Detail', { item })}>
   <Thumbnail
     source={{uri: item.thumbnail}}
   />
   <View>
     <Title>{item.title}</Title>
     <Price>{item.price}</Price>
   </View>
 </ListingItemWrapper>
);

export default ListingItem;
```

在这个代码块中，您从`styled-components/native`中导入`styled`和您想要样式化的 React Native 组件。文件底部导出的`ListingItem`组件接受一个`item`和一个`navigation`属性，以在创建的组件中显示这些数据并处理导航。就像我们在样式化的`Image`组件中看到的那样，`source`属性被赋予一个对象，以显示来自模拟 API 的缩略图。

1.  现在，应该将这个`ListingItem`组件导入到`Screens/Home.js`中，`FlatList`将使用它来显示列表。这个组件接受`item`和`navigation`作为属性，如下所示：

```jsx
import React from 'react';
- import { FlatList, View, Text, TouchableOpacity } from 'react-native';
+ import { FlatList, View } from 'react-native';
import styled from 'styled-components/native';
+ import ListingItem from '../Components/Listing/ListingItem'

...
const Home = ({ navigation }) => {
  ...

  return (
    <ListingsWrapper>
      {!loading && !error && <Listings
        data={data}
        keyExtractor={item => String(item.id)}
-       renderItem={({item}) => (
-         <TouchableOpacity onPress={() => navigation.navigate('Detail', { item })}>
-           <Text>{item.title}</Text>
-         </TouchableOpacity>
-       )}
+       renderItem={({item}) => <ListingItem item={item} />}
      />}
    </ListingsWrapper>
  );
};

export default Home;
```

在 React Native 中，样式规则是针对组件的，这意味着`Text`组件只能接受由 React Native 为该组件指定的样式规则。当您尝试添加不受支持的样式规则时，您将收到一个错误和该组件的所有可能的样式规则的列表。请注意，`styled-components`会自动为您重命名样式规则，以匹配 React Native 中的样式语法。

经过这些更改，您将向应用程序添加了第一个`styled-components`。当您使用 iOS 模拟器或运行 iOS 的设备时，您的应用程序应该如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/a6a3a96c-c928-4c90-ac6d-f7a551f9cc5a.png)

到目前为止，由于我们尚未向应用程序添加任何特定于平台的样式，因此 iOS 和 Android 上的样式应该看起来相似。这将在本节的下一部分中完成，在该部分中，您将探索根据应用程序运行的平台而不同的多种添加样式的方法。

# iOS 和 Android 的样式差异

在设计应用程序时，您可能希望为 iOS 和 Android 设置不同的样式规则，例如，以更好地匹配 Android 操作系统的样式。有多种方法可以将不同的样式规则应用于不同的平台；其中一种方法是使用`Platform`模块，该模块可以从 React Native 中导入。

让我们尝试通过向`navigator`选项卡中的选项卡添加图标，并为 iOS 和 Android 设置不同的图标。

1.  首先，从 Expo 中将图标导入到`App.js`文件中。Expo 提供了许多图标集。对于此应用程序，您将导入`Ionicons`图标集：

```jsx
import React from 'react';
+ import { Ionicons } from '@expo/vector-icons';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';
import Home from './Screens/Home';
import Detail from './Screens/Detail';
import Settings from './Screens/Settings';

const HomeStack = createStackNavigator({
  ...
```

1.  创建选项卡导航器时，您可以定义应该添加到每个路由选项卡的图标。因此，您需要在路由对象中创建一个`defaultNavigationOptions`字段，该字段应包含一个`tabBarIcon`字段。在此字段中，您需要从`navigation`属性中获取当前路由，并返回此路由的图标：

```jsx
...

const AppNavigator = createBottomTabNavigator({
  Home: HomeStack,
  Settings: SettingsStack,
- }, { initialRouteName: 'Home' });
+ }, {
+  initialRouteName: 'Home',
+  defaultNavigationOptions: ({ navigation }) => ({
+    tabBarIcon: () => {
+      const { routeName } = navigation.state;

+      let iconName;
+      if (routeName === 'Home') {
+        iconName = `ios-home`;
+      } else if (routeName === 'Settings') {
+        iconName = `ios-settings`;
+      }

+      return <Ionicons name={iconName} size={20} />;
+    }
+  })
});

export default createAppContainer(AppNavigator);
```

3. 要区分 iOS 和 Android，您需要从`react-native`中导入`Platform`模块。使用此模块，您可以通过检查`Platform.OS`的值是否为`ios`或`android`来检查您的移动设备是运行 iOS 还是 Android。必须将该模块导入以下代码块中：

```jsx
import React from 'react';
+ import { Platform } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';
import { createBottomTabNavigator } from 'react-navigation-tabs';
import Home from './Screens/Home';
import Detail from './Screens/Detail';
import Settings from './Screens/Settings';

const HomeStack = createStackNavigator({
  ...
```

1.  使用`Platform`模块，您可以更改导航器中每个选项卡呈现的图标。除了为 iOS 设计的图标外，`Ionicons`还具有基于 Material Design 的 Android 设计图标，可以像这样使用：

```jsx
...

const AppNavigator = createBottomTabNavigator({
  Home: HomeStack,
  Settings: SettingsStack,
}, {
  initialRouteName: 'Home',
  defaultNavigationOptions: ({ navigation }) => ({
    tabBarIcon: () => {
      const { routeName } = navigation.state;

      let iconName;
      if (routeName === 'Home') {
-       iconName = `ios-home`;
+       iconName = `${Platform.OS === 'ios' ? 'ios' : 'md'}-home`;
      } else if (routeName === 'Settings') {
-       iconName = `ios-settings`;
+       iconName = `${Platform.OS === 'ios' ? 'ios' : 'md'}-settings`;
      }

      return <Ionicons name={iconName} size={20} />;
    }
  }),
});

export default createAppContainer(AppNavigator);
```

当您在 Android 移动设备上运行应用程序时，`navigator`选项卡将显示基于 Material Design 的图标。如果您使用的是苹果设备，它将显示不同的图标；您可以将`Platform.OS === 'ios'`条件更改为`Platform.OS === 'android'`，以将 Material Design 图标添加到 iOS 中。

1.  显示的图标是黑色的，而活动和非活动标签的标签具有不同的颜色。您可以通过更改配置对象来指定图标和标签在活动和非活动状态下的颜色。在`tabBarIcon`字段之后，您可以创建一个名为`tabBarOptions`的新字段，并将`activeTintColor`和`inActiveTintColor`字段添加到其中，如下所示：

```jsx
...
const AppNavigator = createBottomTabNavigator({
  Home: HomeStack,
  Settings: SettingsStack,
}, {
  initialRouteName: 'Home',
  defaultNavigationOptions: ({ navigation }) => ({
    tabBarIcon: () => {
      const { routeName } = navigation.state;

      let iconName;
      if (routeName === 'Home') {
        iconName = `${Platform.OS === 'ios' ? 'ios' : 'md'}-home`;
      } else if (routeName === 'Settings') {
        iconName = `${Platform.OS === 'ios' ? 'ios' : 'md'}-settings`;
      }

      return <Ionicons name={iconName} size={20} />;
    },
+   tabBarOptions: {
+      activeTintColor: 'blue',
+      inactiveTintColor: '#556',
+   },
  })
});

export default createAppContainer(AppNavigator);
```

1.  这只改变了标签的值，但活动和非活动的色调颜色值也可以在`tabBarIcon`字段上使用`tintColor`属性。这个值可以传递给`Ionicons`来改变图标的颜色：

```jsx
...

const AppNavigator = createBottomTabNavigator({
  Home: HomeStack,
  Settings: SettingsStack,
}, {
  initialRouteName: 'Home',
  defaultNavigationOptions: ({ navigation }) => ({
-   tabBarIcon: () => {
+   tabBarIcon: ({ tintColor }) => {
      const { routeName } = navigation.state;

      let iconName;
      if (routeName === 'Home') {
        iconName = `${Platform.OS === 'ios' ? 'ios' : 'md'}-home`;
      } else if (routeName === 'Settings') {
        iconName = `${Platform.OS === 'ios' ? 'ios' : 'md'}-settings`;
      }

-     return <Ionicons name={iconName} size={20} />;
+     return <Ionicons name={iconName} size={20} color={tintColor} />;
    },
    tabBarOptions: {
      activeTintColor: 'blue',
      inactiveTintColor: '#556',
    },
  }),
});

export default createAppContainer(AppNavigator);
```

现在，当您查看主屏幕时，选项卡图标和标签都会呈蓝色，而设置选项卡将呈灰色。此外，无论您是在模拟器上还是在移动设备上运行应用程序，显示的图标都会有所不同。如果您使用 iOS，应用程序应该如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/9222c634-8eda-4ae6-b05d-2ed7a4a6279d.png)

另一个可以进行样式设置的页面是“详情”屏幕。对于这个屏幕，您也可以选择在 iOS 和 Android 之间进行样式上的差异。如前所述，有多种方法可以做到这一点；除了使用`Platform`模块之外，您还可以使用特定于平台的文件扩展名。任何具有`*.ios.js`或`*.android.js`扩展名的文件都只会在扩展名指定的平台上呈现。您不仅可以应用不同的样式规则，还可以在不同平台上进行功能上的变化：

1.  为了在运行 Android 的移动设备上创建一个特定的“详情”屏幕，您需要创建一个名为`Components/Listing/ListingDetail.android.js`的新文件。这个文件里面将包含以下代码：

```jsx
import React from 'react';
import styled from 'styled-components/native';
import { Image, Text, View, Dimensions } from 'react-native';

const ListingDetailWrapper = styled(View)`
  display: flex;
`;

const Details = styled(View)`
  padding: 5%;
`

export const Title = styled(Text)`
  flex-wrap: wrap;
  width: 99%;
  font-size: 30px;
`

export const Price = styled(Text)`
  font-weight: bold;
  font-size: 20px;
  color: blue;
`

const Thumbnail = styled(Image)`
  width: 100%;
  height: ${Dimensions.get('window').width};
`

const ListingDetail = ({ item }) => (
  <ListingDetailWrapper>
    <Thumbnail
      source={{uri: item.thumbnail}}
    />
    <Details>
      <Title>{item.title}</Title>
      <Price>{item.price}</Price>
    </Details>
  </ListingDetailWrapper>
);

export default ListingDetail;
```

正如您所看到的，一些组件将由`ListingDetail`组件呈现。还从`react-native`中导入了`Dimensions`模块。这个模块可以帮助您获取应用程序正在运行的设备的屏幕尺寸。通过获取宽度，您可以在用户屏幕的整个宽度上显示图像。

1.  对于运行 iOS 的设备，您也可以做同样的事情，但这次您需要创建一个名为`Components/Listing/ListingDetail.ios.js`的新文件。这个文件将包含在 Android 上运行的代码的变体，其中图像将使用`Dimensions`模块在整个屏幕高度上显示。iOS 的`ListingDetail`组件可以通过将以下代码块粘贴到该文件中来创建：

```jsx
import React from 'react';
import styled from 'styled-components/native';
import { Image, Text, View, Dimensions } from 'react-native';

const ListingDetailWrapper = styled(View)`
  display: flex;
`;

const Details = styled(View)`
  position: absolute;
  top: 0;
  padding: 5%;
  width: 100%;
  background: rgba(0, 0, 255, 0.1);
`

export const Title = styled(Text)`
  flex-wrap: wrap;
  width: 99%;
  font-size: 30px;
`

export const Price = styled(Text)`
  font-weight: bold;
  font-size: 20px;
  color: blue;
`

const Thumbnail = styled(Image)`
  width: 100%;
  height: ${Dimensions.get('window').height};
`

const ListingDetail = ({ item }) => (
  <ListingDetailWrapper>
    <Thumbnail
      source={{uri: item.thumbnail}}
    />
    <Details>
      <Title>{item.title}</Title>
      <Price>{item.price}</Price>
    </Details>
  </ListingDetailWrapper>
);

export default ListingDetail;
```

1.  要在应用程序中显示这些组件中的一个，需要对`Screens/Detail.js`文件进行一些更改。`ListingDetail`组件应该被导入到这个文件中，并使用`item`属性返回：

```jsx
import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
+ import ListingDetail from '../Components/Listing/ListingDetail';

const Detail = ({ navigation }) => {
  const item = navigation.getParam('item', {});

  return (
-  <View style={styles.container}>
+  <ListingDetail item={item} />
-  </View>
  )
};

- const styles = StyleSheet.create({
-  container: {
-    flex: 1,
-    backgroundColor: '#fff',
-    alignItems: 'center',
-    justifyContent: 'center',
-  },
- });

export default Detail;
```

您的应用程序现在在 iOS 和 Android 上有两个不同版本的详细屏幕，React Native 将确保具有正确扩展名的文件在该操作系统上运行。您可以通过比较在 Android 模拟器或移动设备上运行的应用程序与以下截图来检查这一点，该截图是从 iOS 设备上获取的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/bb97a0eb-ee44-4098-946e-699afe265f14.png)

通过这些最后的更改，您已经创建了您的第一个 React Native 应用程序，该应用程序将在 Android 和 iOS 设备上运行，并实现了基本的路由和样式。

# 摘要

在本章中，您使用 React Native 为 iOS 和 Android 移动设备创建了一个房源应用程序。Expo 用于创建应用程序的第一个版本，并提供了许多功能以平滑开发人员的体验。`react-navigation`包用于处理移动应用程序的不同类型的路由，而`styled-components`用于处理这个 React Native 应用程序的样式。

由于这可能是您对 React Native 的第一次介绍，如果一开始并不清楚一切，您不必感到难过。本章中学到的基础知识应该提供了一个合适的基线，以便我们可以继续您的移动应用开发之旅。在下一章中，您将创建的项目将进一步建立在这些原则之上，并处理诸如动画之类的功能，同时我们将创建一个*井字棋*游戏。

# 进一步阅读

+   要了解有关 React Navigation 中自定义标题的更多信息，请查看此链接：[`reactnavigation.org/docs/en/headers.html`](https://reactnavigation.org/docs/en/headers.html)。

+   您可以在这里找到 Expo 图标的列表：[`expo.github.io/vector-icons/`](https://expo.github.io/vector-icons/)。
