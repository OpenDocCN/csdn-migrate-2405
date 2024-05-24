# Vue2 Web 开发完全手册（五）

> 原文：[`zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070`](https://zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：构建电子商务商店-添加结账功能

在过去的几章中，我们创建了一个电子商务商店。到目前为止，我们已经创建了一个产品页面，允许我们查看图像和产品变体，可能是尺寸或样式。我们还创建了一个带有过滤器和分页的类别页面，包括一个主页类别页面，其中包含特定的选定产品。

我们的用户可以浏览和筛选产品，并查看有关特定产品的更多信息。现在我们要做的是：

+   构建功能，允许用户将产品添加到购物篮中并从中删除

+   允许用户结账

+   添加订单确认页面

提醒一下-我们不会获取任何账单详细信息，但我们会创建一个订单确认屏幕。

# 创建购物篮数组占位符

为了帮助我们在整个应用程序中持久保存购物篮中的产品，我们将把用户选择的产品存储在 Vuex 存储中。这将以对象数组的形式存在。每个对象将包含几个关键信息，这些信息将允许我们在不必每次查询 Vuex 存储时都能显示购物篮中的产品。它还允许我们存储有关产品页面当前状态的详细信息-当选择变体时，记住图像更新。

我们将为添加到购物篮中的每个产品存储以下详细信息：

+   产品标题

+   产品句柄，以便我们可以链接回产品

+   选定的变体标题（在选择框中显示）

+   当前选定的图像，以便我们可以在结账时显示适当的图像

+   变体详细信息，包括价格、重量和其他细节

+   变体 SKU，这将帮助我们确定产品是否已经添加

+   数量，用户已添加到购物篮中的物品数量

由于我们将把所有这些信息存储在一个对象中，该对象包含在一个数组中，我们需要在存储中创建一个占位符数组。在存储的`state`对象中添加一个名为`basket`的新键，并将其设置为空数组：

```js
const store = new Vuex.Store({
  state: {
    products: {},
    categories: {},

    categoryHome: {
      title: 'Welcome to the Shop',
      handle: 'home',
      products: [
        ...
      ]
    },

    basket: []

  },

  mutations: {
    ...
  },

  actions: {
    ...
  },

  getters: {
    ...
  }
});
```

# 将产品信息添加到存储中

准备好我们的`basket`数组来接收数据后，我们现在可以创建一个 mutation 来添加产品对象。打开`ProductPage.js`文件，更新`addToBasket`方法，调用`$store`的 commit 函数，而不是我们放置的`alert`。

我们需要将产品添加到购物篮的所有所需信息都存储在`ProductPage`组件上，因此我们可以使用`this`关键字将组件实例传递给`commit()`函数。当我们构建突变时，这将变得清晰。

将函数调用添加到`ProductPage`方法中：

```js
methods: {
  ...

 addToBasket() {
 this.$store.commit('addToBasket', this);
 }
}
```

# 创建存储突变以将产品添加到购物篮中

转到 Vuex 存储并创建一个名为`addToBasket`的新突变。这将接受`state`作为第一个参数，组件实例作为第二个参数。通过传递实例，我们可以访问组件上的变量、方法和计算值。

```js
mutations: {
  products(state, payload) {
    ...
  },

  categories(state, payload) {
    ...
  },

 addToBasket(state, item) {

 }
}
```

现在，我们可以继续将产品添加到`basket`数组中。第一步是添加具有所述属性的产品对象。由于它是一个数组，我们可以使用`push()`函数来添加对象。

接下来，使用`item`及其属性构建对象，将对象添加到数组中。通过访问`ProductPage`组件，我们可以使用`variantTitle`方法构建变体标题，该标题将显示在选择框中。默认情况下，将数量设置为`1`：

```js
addToBasket(state, item) {
  state.basket.push({
 sku: item.variation.sku,
 title: item.product.title,
 handle: item.slug,
 image: item.image,
 variationTitle: item.variantTitle(item.variation),
 variation: item.variation,
 quantity: 1
 });
}
```

现在，将产品添加到`basket`数组中。然而，当您将两个相同的商品添加到购物篮时，会出现一个问题。它不会增加`quantity`，而是简单地添加第二个产品。

可以通过检查数组中是否已存在`sku`来解决此问题。如果存在，我们可以增加该商品的数量，如果不存在，我们可以将新商品添加到`basket`数组中。每个产品的每个变体的`sku`是唯一的。或者，我们可以使用条形码属性。

使用原生的`find` JavaScript 函数，我们可以识别出具有与传入的 SKU 相匹配的任何产品：

```js
addToBasket(state, item) {
 let product = state.basket.find(p => {
 if(p.sku == item.variation.sku) {
 }
 });

  state.basket.push({
    sku: item.variation.sku,
    title: item.product.title,
    handle: item.slug,
    image: item.image,
```

```js
    variationTitle: item.variantTitle(item.variation),
    variation: item.variation,
    quantity: 1
  });
}
```

如果匹配，我们可以使用 JavaScript 中的`++`符号将该对象的数量增加一。如果不匹配，我们可以将新对象添加到`basket`数组中。使用`find`函数时，如果产品存在，我们可以返回该产品。如果不存在，我们可以添加一个新商品：

```js
addToBasket(state, item) {
  let product = state.basket.find(p => {
    if(p.sku == item.variation.sku) {
      p.quantity++;

 return p;
    }
  });

  if(!product) {
    state.basket.push({
      sku: item.variation.sku,
      title: item.product.title,
      handle: item.slug,
      image: item.image,
      variationTitle: item.variantTitle(item.variation),
      variation: item.variation,
      quantity: 1
    });
 }
}
```

现在，当商品添加到购物篮中时，购物篮会被填充，并且在已存在时会递增。

为了提高应用的可用性，当用户将商品添加到购物篮时，我们应该给予用户一些反馈。可以通过更新“添加到购物篮”按钮并在网站头部显示一个带有指向购物篮的链接的产品计数来实现这一点。

# 在添加商品时更新“添加到购物篮”按钮

作为对我们商店的可用性改进，当用户点击“添加到购物篮”按钮时，我们将更新该按钮。它将变为“已添加到您的购物篮”，并在一段时间内应用一个类，例如两秒钟，然后返回到之前的状态。CSS 类将允许您对按钮进行不同的样式设置，例如将背景改为绿色或稍微进行变换。

通过在组件上使用一个数据属性来实现这一点，将其设置为`true`和`false`，当商品被添加时。CSS 类和文本将使用此属性来确定要显示的内容，而`setTimeout` JavaScript 函数将更改属性的状态。

打开`ProductPage`组件，并在数据对象中添加一个名为`addedToBasket`的新键。默认将其设置为`false`：

```js
data() {
  return {
    slug: this.$route.params.slug,
    productNotFound: false,
    image: false,
    variation: false,
    addedToBasket: false
  }
}
```

更新按钮文本以适应这个变化。由于已经有一个三元`if`，我们将在其中嵌套另一个。如果需要，这可以抽象成一个方法。

在按钮中，用一个额外的三元运算符替换`Add to basket`条件，取决于`addedToBasket`变量是否为 true。我们还可以根据此属性添加一个条件类：

```js
<button 
  @click="addToBasket()" 
  :class="(addedToBasket) ? 'isAdded' : ''" 
  :disabled="!variation.quantity"
>
  {{ 
    (variation.quantity) ? 
    ((addedToBasket) ? 'Added to your basket' : 'Add to basket') : 
    'Out of stock'
```

```js
  }}
</button>
```

刷新应用并导航到一个产品页面，确保正确的文本被显示。将`addedToBasket`变量更新为`true`，以确保一切都显示正常。然后将其设置回`false`。

接下来，在`addToBasket()`方法中，将该属性设置为 true。当商品被添加到购物篮时，这将更新文本：

```js
addToBasket() {
  this.$store.commit('addToBasket', this);

 this.addedToBasket = true;
}
```

当您点击按钮时，文本现在会更新，但它永远不会重置。在之后添加一个`setTimeout` JavaScript 函数，它会在一定时间后将其设置回`false`：

```js
addToBasket() {
  this.$store.commit('addToBasket', this);

  this.addedToBasket = true;
  setTimeout(() => this.addedToBasket = false, 2000);
}
```

`setTimeout`的时间单位是毫秒，所以`2000`等于两秒。根据需要随意调整和修改这个数字。

最后一个添加是，如果变体被更新或产品被更改，将此值重置为`false`。将该语句添加到两个`watch`函数中：

```js
watch: {
  variation(v) {
    if(v.hasOwnProperty('image')) {
      this.updateImage(v.image);
    }

    this.addedToBasket = false;
  },

  '$route'(to) {
    this.slug = to.params.slug;
    this.addedToBasket = false;
  }
}
```

# 在应用的页眉中显示产品数量

在网站的页眉中显示购物车链接以及购物车中的商品数量是常见的做法。为了实现这一点，我们将使用一个 Vuex getter 来计算并返回购物篮中的商品数量。

打开`index.html`文件并在应用程序 HTML 中添加一个`<header>`元素，并插入一个占位符`span` - 一旦我们设置了路由，我们将把它转换为链接。在 span 中，输出一个`cartQuantity`变量：

```js
<div id="app">
  <header>
 <span>Cart {{ cartQuantity }}</span>
 </header>
  <main>
    <router-view></router-view>
  </main>
  <aside>
    <router-view name="sidebar"></router-view>
  </aside>
</div>
```

转到你的`Vue`实例并创建一个包含`cartQuantity`函数的`computed`对象：

```js
new Vue({
  el: '#app',

  store,
  router,

 computed: {
 cartQuantity() {

 }
 },

  created() {
    CSV.fetch({url: './data/csv-files/bicycles.csv'}).then(data => {
      this.$store.dispatch('initializeShop', this.$formatProducts(data));
    });
  }
});
```

如果我们的标题中的商品比购物车链接多，最好将其抽象为一个单独的组件，以保持方法、布局和函数的封装。然而，由于在我们的示例应用程序中只会显示这一个链接，将函数添加到`Vue`实例中就足够了。

在 store 中创建一个名为`cartQuantity`的新 getter。作为占位符，返回`1`。`state`将被用于计算数量，所以现在确保将其传递给函数：

```js
getters: {
  ...

 cartQuantity: (state) => { 
 return 1;
 }
}
```

返回到你的`Vue`实例并返回 getter 的结果。理想情况下，我们希望在括号中显示`basket`的数量，但只有在有商品时才显示括号。在计算函数中，检查这个 getter 的结果，并在结果存在时输出带有括号的结果：

```js
cartQuantity() {
  const quantity = this.$store.getters.cartQuantity;
 return quantity ? `(${quantity})` : '';
}
```

在 Vuex getter 中更改结果应该会显示带括号的数字或根本不显示任何内容。

# 计算购物篮数量

有了显示逻辑，我们现在可以继续计算购物篮中有多少商品。我们可以计算`basket`数组中的商品数量，但是这只会告诉我们现在有多少不同的商品，而不是同一种商品被添加了多次。

相反，我们需要遍历购物篮中的每个商品并将数量相加。创建一个名为`quantity`的变量并将其设置为`0`。遍历购物篮中的商品并将`item.quantity`变量添加到`quantity`变量中。最后，返回我们的变量与正确的总和：

```js
cartQuantity: (state) => {
 let quantity = 0;
 for(let item of state.basket) {
 quantity += item.quantity;
 }
 return quantity;
}
```

转到应用程序并添加一些商品到购物篮中，以验证购物篮数量是否被正确计算。

# 最终确定 Shop Vue-router 的 URL

我们现在处于一个可以最终确定我们商店的 URL 的阶段 - 包括创建重定向和结账链接。回顾第八章，*介绍 Vue-Router 和加载基于 URL 的组件*，我们可以看到我们缺少哪些。这些是：

+   `/category` - 重定向到`/`

+   `/product` - 重定向到`/`

+   `/basket` - 加载`OrderBasket`组件

+   `/checkout` - 加载`OrderCheckout`组件

+   `/complete` - 加载`OrderConfirmation`组件

在路由数组的适当位置创建重定向。在路由数组的底部，为`Order`组件创建三个新路由：

```js
routes: [
  {
    path: '/',
    name: 'Home',
    ...
  },
  {
 path: '/category',
 redirect: {name: 'Home'}
 },
  {
    path: '/category/:slug',
    name: 'Category',
    ...
  },
  {
 path: '/product',
 redirect: {name: 'Home'}
 },
  {
    path: '/product/:slug',
    name: 'Product',
    component: ProductPage
  },
  {
path: '/basket',
 name: 'Basket',
 component: OrderBasket
 },
 {
 path: '/checkout',
 name: 'Checkout',
 component: OrderCheckout
 },
 {
 path: '/complete',
 name: 'Confirmation',
 component: OrderConfirmation
 },

  {
    path: '/404', 
    alias: '*',
    component: PageNotFound
  }
]
```

我们现在可以使用`router-link`来更新应用程序标题中的占位符`<span>`：

```js
<header>
  <router-link :to="{name: 'Basket'}">Cart {{ cartQuantity }}</router-link>
</header>
```

# 构建订单流程和 ListProducts 组件

对于结账的三个步骤，我们将在所有三个步骤中使用相同的组件：`ListProducts`组件。在`OrderCheckout`和`OrderConfirmation`组件中，它将处于固定的、不可编辑的状态，而在`OrderBasket`组件中，用户需要能够更新数量和删除物品。

由于我们将在结账时进行操作，我们需要在`basket`数组中存在产品。为了避免每次刷新应用程序时都要查找产品并将其添加到购物篮中，我们可以通过在存储中硬编码一个数组来确保`basket`数组中有一些产品。

为了实现这一点，导航到一些产品并将它们添加到购物篮中。确保有一些产品和数量进行测试。接下来，在浏览器中打开 JavaScript 控制台并输入以下命令：

```js
console.log(JSON.stringify(store.state.basket));
```

这将输出一个您的产品数组的字符串。将其复制并粘贴到您的存储中，替换`basket`数组：

```js
state: {
  products: {},
  categories: {},

  categoryHome: {
    title: 'Welcome to the Shop',
    handle: 'home',
    products: [
      ...
    ]
  },

  basket: [{"sku":...}]
},
```

页面加载时，标题中的购物车计数应更新为您添加的正确数量的物品。

现在我们可以继续构建我们的结账流程了。购物篮中的产品显示比结账和订单确认屏幕更复杂，因此我们将反向工作。从订单确认页面开始，然后转到结账页面，在前往购物篮之前增加更多复杂性，添加退出产品的功能。

# 订单确认屏幕

订单确认屏幕是在订单完成后显示的屏幕。它确认购买的物品，并可能包括预计的交货日期。

在`OrderConfirmation.js`文件中创建一个包含`<h1>`和与订单完成相关的一些相关内容的模板：

```js
const OrderConfirmation = {
  name: 'OrderConfirmation',

  template: `<div>
    <h1>Order Complete!</h1>
    <p>Thanks for shopping with us - you can expect your products within 2 - 3 working days</p>
  </div>`
};
```

在浏览器中打开应用程序，将产品添加到购物篮中并完成订单以确认其是否正常工作。下一步是包含`ListProducts`组件。首先，确保`ListProducts`组件正确初始化并具有初始模板：

```js
const ListPurchases = {
  name: 'ListPurchases',

  template: `<table></table>`
};
```

将`components`对象添加到`OrderConfirmation`组件中，并包含`ListProducts`组件。接下来，在模板中包含它：

```js
const OrderConfirmation = {
  name: 'OrderConfirmation',

  template: `<div>
    <h1>Order Complete!</h1>
    <p>Thanks for shopping with us - you can expect your products within 2 - 3 working days</p>
    <list-purchases />
  </div>`,

 components: {
 ListPurchases
 }
};
```

再次打开`ListPurchases`组件以开始显示产品。该组件的默认状态将是列出购物篮中的产品，以及所选的变体。每个产品的价格将被显示出来，如果数量大于一，则还会显示价格。最后，将显示一个总计。

第一步是将购物篮列表放入我们的组件中。创建一个带有`products`函数的`computed`对象。这个函数应该返回购物篮中的产品：

```js
const ListPurchases = {
  name: 'ListPurchases',

  template: `<table></table>`,

  computed: {
 products() {
 return this.$store.state.basket;
 }
 }
};
```

现在我们可以在表格中循环遍历购物篮中的产品，并显示所需的信息。这包括缩略图、产品和变体标题、价格、数量和项目的总价格。还要在表格中添加一个标题行，以便用户知道每列的内容：

```js
  template: `<table>
    <thead>
      <tr>
        <th></th>
        <th>Title</th>
        <th>Unit price</th>
        <th>Quantity</th>
        <th>Price</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="product in products">
        <td>
          <img 
            :src="product.image.source" 
            :alt="product.image.alt || product.variationTitle"
            width="80"
          >
        </td>
        <td>
          <router-link :to="{name: 'Product', params: {slug: product.handle}}">
            {{ product.title }}
          </router-link><br>
          {{ product.variationTitle }}
        </td>
        <td>{{ product.variation.price }}</td>
        <td>{{ product.quantity }}</td>
        <td>{{ product.variation.price * product.quantity }}</td>
      </tr>
    </tbody>
  </table>`,
```

请注意，每行的价格只是单位价格乘以数量。现在我们有了用户购买的标准产品列表。

# 使用 Vue 过滤器格式化价格

价格目前是一个整数，因为它在数据中是这样的。在产品页面上，我们只是在价格前面加了一个`$`符号来表示价格，然而，现在正是利用 Vue 过滤器的绝佳机会。过滤器允许您在模板中操作数据，而无需使用方法。过滤器可以链接在一起，用于执行通常的单一修改，例如将字符串转换为小写或将数字格式化为货币。

过滤器使用管道（`|`）运算符。例如，如果我们有一个将文本转换为小写的过滤器，可以像下面这样使用它：

```js
{{ product.title | lowercase }}
```

过滤器在组件的`filters`对象中声明，并接受一个输出前置参数。

在`ListPurchases`组件中创建一个`filters`对象，并在其中创建一个名为`currency()`的函数。这个函数接受一个名为`val`的参数，并应该返回该变量的值：

```js
filters: {
  currency(val) {
    return val;
  }
},
```

现在我们可以使用这个函数来操作价格整数。在模板中将过滤器添加到单位价格和总价格中：

```js
<td>{{ product.variation.price | currency }}</td>
<td>{{ product.quantity }}</td>
<td>{{ product.variation.price * product.quantity | currency }}</td>
```

在浏览器中您不会注意到任何变化，因为我们还没有对值进行操作。更新函数以确保数字保留两位小数，并在前面加上`$`符号：

```js
filters: {
  currency(val) {
    return ' + val.toFixed(2);
  }
},
```

我们的价格现在已经很好地格式化并正确显示。

# 计算总价格

购物清单的下一个添加是购物篮的总价值。这需要以与我们之前计算购物篮数量的方式进行计算。

创建一个新的`computed`函数标题为`totalPrice`。该函数应该循环遍历产品并累加价格，考虑到任何多个数量：

```js
totalPrice() {
  let total = 0;

  for(let p of this.products) {
    total += (p.variation.price * p.quantity);
  }

  return total;
}
```

现在我们可以更新模板以包括总价格 - 确保我们通过`currency`过滤器传递它：

```js
template: `<table>
  <thead>
    <tr>
      <th></th>
      <th>Title</th>
      <th>Unit price</th>
      <th>Quantity</th>
      <th>Price</th>
    </tr>
  </thead>
  <tbody>
    <tr v-for="product in products">
      <td>
        <img 
          :src="product.image.source" 
          :alt="product.image.alt || product.variationTitle"
          width="80"
        >
      </td>
      <td>
        <router-link :to="{name: 'Product', params: {slug: product.handle}}">
          {{ product.title }}
        </router-link><br>
        {{ product.variationTitle }}
      </td>
      <td>{{ product.variation.price | currency }}</td>
      <td>{{ product.quantity }}</td>
      <td>{{ product.variation.price * product.quantity | currency }}</td>
    </tr>
  </tbody>
  <tfoot>
 <td colspan="4">
 <strong>Total:</strong>
 </td>
 <td>{{ totalPrice | currency }}</td>
 </tfoot>
</table>`,
```

# 创建一个订单结账页面

我们的`OrderCheckout`页面的构成与`OrderConfirmation`页面类似 - 但是，在真实的商店中，这将是付款之前的页面。该页面允许用户在导航到付款页面之前填写其帐单和交付详细信息。复制`OrderConfirmation`页面并更新标题和信息文本：

```js
const OrderCheckout = {
  name: 'OrderCheckout',

  template: '<div>;
    <h1>Order Confirmation</h1>
    <p>Please check the items below and fill in your details to complete your order</p>
    <list-purchases />
  </div>',

  components: {
    ListPurchases
  }
};
```

在`<list-purchases />`组件下方，创建一个表单，包含几个字段，以便我们可以收集帐单和交付名称和地址。对于这个示例，只需收集姓名、地址的第一行和邮政编码：

```js
template: '<div>
  <h1>Order Confirmation</h1>
  <p>Please check the items below and fill in your details to complete your order</p>
  <list-purchases />

  <form>
 <fieldset>
 <h2>Billing Details</h2>
 <label for="billingName">Name:</label>
 <input type="text" id="billingName">
 <label for="billingAddress">Address:</label>
 <input type="text" id="billingAddress">
 <label for="billingZipcode">Post code/Zip code:</label>
 <input type="text" id="billingZipcode">
 </fieldset>
 <fieldset>
 <h2>Delivery Details</h2>
 <label for="deliveryName">Name:</label>
 <input type="text" id="deliveryName">
 <label for="deliveryAddress">Address:</label>
 <input type="text" id="deliveryAddress">
 <label for="deliveryZipcode">Post code/Zip code:</label>
 <input type="text" id="deliveryZipcode">
 </fieldset>
 </form>
</div>',
```

现在我们需要创建一个数据对象，并将每个字段绑定到一个键。为了帮助分组每个集合，为`delivery`和`billing`分别创建一个对象，并在内部创建正确名称的字段：

```js
data() {
  return {
    billing: {
      name: '',
      address: '',
      zipcode: ''
    },
    delivery: {
      name: '',
      address: '',
      zipcode: ''
    }
  }
}
```

为每个输入添加`v-model`，将其链接到相应的数据键：

```js
<form>
  <fieldset>
    <h2>Billing Details</h2>
    <label for="billingName">Name:</label>
    <input type="text" id="billingName" v-model="billing.name">
    <label for="billingAddress">Address:</label>
    <input type="text" id="billingAddress" v-model="billing.address">
    <label for="billingZipcode">Post code/Zip code:</label>
    <input type="text" id="billingZipcode" v-model="billing.zipcode">
  </fieldset>
  <fieldset>
    <h2>Delivery Details</h2>
    <label for="deliveryName">Name:</label>
    <input type="text" id="deliveryName" v-model="delivery.name">
    <label for="deliveryAddress">Address:</label>
    <input type="text" id="deliveryAddress" v-model="delivery.address">
    <label for="deliveryZipcode">Post code/Zip code:</label>
    <input type="text" id="deliveryZipcode" v-model="delivery.zipcode">
  </fieldset>
</form>
```

下一步是创建一个`submit`方法并整理数据以便能够将其传递给下一个屏幕。创建一个名为`submitForm()`的新方法。由于本示例中不处理付款，所以可以在该方法中路由到确认页面：

```js
methods: {
  submitForm() {
    // this.billing = billing details
    // this.delivery = delivery details

    this.$router.push({name: 'Confirmation'});
  }
}
```

现在我们可以将`submit`事件绑定到表单上，并添加一个提交按钮。与`v-bind:click`属性（或`@click`）类似，Vue 允许您使用`@submit=""`属性将`submit`事件绑定到一个方法上。

在`<form>`元素中添加声明并在表单中创建一个提交按钮：

```js
<form @submit="submitForm()">
  <fieldset>
    ...
  </fieldset>

  <fieldset>
    ...
  </fieldset>

  <input type="submit" value="Purchase items">
</form>
```

在提交表单时，应用程序应将您重定向到我们的确认页面。

# 在地址之间复制详细信息

几个商店都有的一个功能是将交付地址标记为与帐单地址相同。我们可以采用几种方法来实现这一点，您可以根据自己的选择来做。即时选项有：

+   有一个“复制详细信息”按钮 - 这将从帐单复制详细信息到交付，但不会保持它们同步

+   有一个复选框，可以保持两者同步 - 勾选该框会禁用交付框字段，但会填充帐单详细信息

对于这个示例，我们将编写第二个选项。

在两个字段集之间创建一个复选框，通过`v-model`将其绑定到数据对象中的一个属性`sameAddress`：

```js
<form @submit="submitForm()">
  <fieldset>
     ...
  </fieldset>
 <label for="sameAddress">
 <input type="checkbox" id="sameAddress" v-model ="sameAddress">
 Delivery address is the same as billing
 </label>
  <fieldset>
    ...
  </fieldset>

  <input type="submit" value="Purchase items">
</form>
```

在数据对象中创建一个新的键，并将其默认设置为`false`：

```js
data() {
  return {
    sameAddress: false,

    billing: {
      name: '',
      address: '',
      zipcode: ''
    },
    delivery: {
      name: '',
      address: '',
      zipcode: ''
    }
  }
},
```

下一步是如果复选框被选中，则禁用 delivery 字段。这可以通过根据复选框的结果激活`disabled`HTML 属性来实现。类似于我们在产品页面上禁用“添加到购物车”按钮的方式，将 delivery 字段上的 disabled 属性绑定到`sameAddress`变量上：

```js
<fieldset>
  <h2>Delivery Details</h2>
  <label for="deliveryName">Name:</label>
  <input type="text" id="deliveryName" v-model="delivery.name" :disabled="sameAddress">
  <label for="deliveryAddress">Address:</label>
  <input type="text" id="deliveryAddress" v-model="delivery.address" :disabled="sameAddress">
  <label for="deliveryZipcode">Post code/Zip code:</label>
  <input type="text" id="deliveryZipcode" v-model="delivery.zipcode" :disabled="sameAddress">
</fieldset>
```

现在勾选复选框将禁用字段，使用户无法输入任何数据。下一步是在两个部分之间复制数据。由于我们的数据对象具有相同的结构，我们可以创建一个`watch`函数，当复选框被选中时，将`delivery`对象设置为与`billing`对象相同。

创建一个新的`watch`对象和函数来处理`sameAddress`变量。如果它为`true`，则将 delivery 对象设置为与 billing 对象相同：

```js
watch: {
  sameAddress() {
    if(this.sameAddress) {
      this.delivery = this.billing;
    }
  }
}
```

添加了`watch`函数后，我们可以输入数据到 billing 地址，勾选复选框，然后 delivery 地址会自动填充。最好的是它们现在保持同步，所以如果你更新 billing 地址，delivery 地址会实时更新。问题出现在当你取消勾选复选框并编辑 billing 地址时，delivery 地址仍然会更新。这是因为我们将这两个对象绑定在一起。

添加一个`else`语句，当复选框未选中时，复制 billing 地址：

```js
watch: {
  sameAddress() {
    if(this.sameAddress) {
      this.delivery = this.billing;
    } else {
 this.delivery = Object.assign({}, this.billing);
 }
  }
}
```

现在我们有一个功能完善的订单确认页面，可以收集账单和交付细节。

# 创建可编辑的购物篮

现在我们需要创建我们的购物篮。它需要以类似于结账和确认页面的方式显示产品，但它需要给用户编辑购物篮内容的能力-删除项目或更新数量。

作为起点，打开`OrderBasket.js`并包含`list-purchases`组件，就像我们在确认页面上所做的那样：

```js
const OrderBasket = {
  name: 'OrderBasket',

  template: `<div>
    <h1>Basket</h1>
    <list-purchases />
  </div>`,

  components: {
    ListPurchases
  }
};
```

接下来我们需要编辑`list-purchases`组件。为了确保我们可以区分视图，我们将添加一个`editable`属性。默认情况下设置为`false`，在购物篮中设置为`true`。在购物篮中的组件中添加这个属性：

```js
template: `<div>
  <h1>Basket</h1>
  <list-purchases :editable="true" />
</div>`,
```

现在我们需要告诉`ListPurchases`组件接受这个参数，以便我们可以在组件内部对其进行操作：

```js
props: {
  editable: {
    type: Boolean,
    default: false
  }
},
```

# 创建可编辑字段

现在我们有一个属性来确定我们的购物篮是否可编辑。这允许我们显示删除链接并使数量成为可编辑框。

在`ListPurchases`组件中，在数量旁边创建一个新的表格单元格，并仅在购买可见时显示它。在这种状态下，将静态数量隐藏。在新的单元格中，添加一个值设置为数量的输入框。我们还将绑定一个`blur`事件到该框。`blur`事件是一个原生 JavaScript 事件，当输入框失去焦点时触发。在失去焦点时，触发一个`updateQuantity`方法。该方法应该接受两个参数：事件，其中包含新的数量，以及该特定产品的 SKU：

```js
<tbody>
  <tr v-for="product in products">
    <td>
      <img 
        :src="product.image.source" 
        :alt="product.image.alt || product.variationTitle"
        width="80"
      >
    </td>
    <td>
      <router-link :to="{name: 'Product', params: {slug: product.handle}}">
        {{ product.title }}
      </router-link><br>
      {{ product.variationTitle }}
    </td>
    <td>{{ product.variation.price | currency }}</td>
    <td v-if="!editable">{{ product.quantity }}</td>
    <td v-if="editable">
      <input 
 type="text"
 :value="product.quantity" 
 @blur="updateQuantity($event, product.sku)"
 >
    </td>
    <td>{{ product.variation.price * product.quantity | currency }}</td>
  </tr>
</tbody>
```

在组件上创建新的方法。该方法应该循环遍历产品，找到具有匹配 SKU 的产品并将数量更新为整数。我们还需要更新存储的结果，以便在页面顶部更新数量。我们将创建一个通用的 mutation，接受带有新值的完整`basket`数组，以允许相同的 mutation 用于产品删除。

创建更新数量并提交名为`updatePurchases`的 mutation：

```js
methods: {
  updateQuantity(e, sku) {
    let products = this.products.map(p => {
      if(p.sku == sku) {
        p.quantity = parseInt(e.target.value);
      }
      return p;
    });

    this.$store.commit('updatePurchases', products);
  }
}
```

在 store 中，创建将`state.basket`设置为 payload 的 mutation：

```js
updatePurchases(state, payload) {
  state.basket = payload;
}
```

现在，更新数量应该更新页面顶部的商品总价和购物车数量。

# 从购物车中删除商品

下一步是让用户能够从购物车中删除商品。在`ListPurchases`组件中创建一个带有点击绑定的按钮。这个按钮可以放在任何你想要的地方 - 我们的示例将其显示为行末的额外单元格。将点击操作绑定到一个名为`removeItem`的方法。这只需要接受一个 SKU 的参数。在`ListPurchases`组件中添加以下内容：

```js
<tbody>
  <tr v-for="product in products">
    <td>
      <img 
        :src="product.image.source" 
        :alt="product.image.alt || product.variationTitle"
        width="80"
      >
    </td>
    <td>
      <router-link :to="{name: 'Product', params: {slug: product.handle}}">
        {{ product.title }}
      </router-link><br>
      {{ product.variationTitle }}
    </td>
    <td>{{ product.variation.price | currency }}</td>
    <td v-if="!editable">{{ product.quantity }}</td>
    <td v-if="editable"><input 
      type="text"
      :value="product.quantity" 
      @blur="updateQuantity($event, product.sku)"
    ></td>
    <td>{{ product.variation.price * product.quantity | currency }}</td>
    <td v-if="editable">
 <button @click="removeItem(product.sku)">Remove item</button>
 </td>
  </tr>
</tbody>
```

创建`removeItem`方法。该方法应该过滤`basket`数组，只返回不匹配传入的 SKU 的对象。一旦结果被过滤，将结果传递给与`updateQuantity()`方法中使用的相同的 mutation：

```js
removeItem(sku) {
  let products = this.products.filter(p => {
    if(p.sku != sku) {
      return p;
    }
  });

  this.$store.commit('updatePurchases', products);
}
```

我们可以做的最后一个改进是如果数量设置为 0，则触发`removeItem`方法。在`updateQuantity`方法中，在循环遍历产品之前检查值。如果它是`0`或不存在，则运行`removeItem`方法 - 通过传递 SKU：

```js
updateQuantity(e, sku) {
  if(!parseInt(e.target.value)) {
 this.removeItem(sku);
 } else {
    let products = this.products.map(p => {
      if(p.sku == sku) {
        p.quantity = parseInt(e.target.value);
      }
      return p;
    });

    this.$store.commit('updatePurchases', products);
  }
},
```

# 完成购物 SPA

最后一步是从`OrderBasket`组件添加到`OrderCheckout`页面的链接。这可以通过链接到`Checkout`路由来完成。有了这个，您的结账就完成了，您的商店也完成了！在购物篮中添加以下链接：

```js
template: `<div>
  <h1>Basket</h1>
  <list-purchases :editable="true" />
  <router-link :to="{name: 'Checkout'}">Proceed to Checkout</router-link>
</div>`,
```

# 摘要

干得好！您已经使用`Vue.js`创建了一个完整的商店单页面应用程序。您已经学会了如何列出产品及其变体，以及如何将特定的变体添加到购物篮中。您已经学会了如何创建商店过滤器和类别链接，以及创建可编辑的购物篮。

就像任何事情一样，总是有改进的空间。为什么不尝试一些这些想法呢？

+   使用`localStorage`持久化购物篮-这样添加到购物篮中的产品在访问和用户按下刷新之间保留

+   根据购物篮中产品的重量属性计算运费-使用 switch 语句创建带有不同范围的运费

+   允许从类别列表页面将没有变体的产品添加到购物篮中

+   当在类别页面上过滤某个变体时，指示哪些产品缺货

+   您自己的任何想法！


# 第十二章：使用 Vue Dev Tools 和测试您的 SPA

在过去的 11 章中，我们使用`Vue.js`开发了几个**单页应用程序**（**SPAs**）。尽管开发是创建 SPA 的重要部分，但测试也是创建任何 JavaScript Web 应用程序的重要组成部分。

Vue 开发者工具在 Chrome 和 Firefox 中提供了对在某个视图中使用的组件或 Vuex 存储的当前状态的深入洞察 - 以及从 JavaScript 中发出的任何事件。这些工具允许您在开发过程中检查和验证应用程序中的数据，以确保一切都正常。

SPA 测试的另一方面是自动化测试。您编写的条件、规则和路由用于自动化应用程序中的任务，允许您指定输出应该是什么，并且测试运行条件以验证结果是否匹配。

在本章中，我们将：

+   涵盖使用我们开发的应用程序的 Vue 开发者工具的使用

+   了解测试工具和应用程序的概述

# 使用 Vue.js 开发者工具

Vue 开发者工具适用于 Chrome 和 Firefox，并可以从 GitHub（[`github.com/vuejs/vue-devtools`](https://github.com/vuejs/vue-devtools)）下载。安装后，它们成为浏览器开发者工具的扩展。例如，在 Chrome 中，它们出现在审核标签之后。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/e359dd13-20e7-4814-83e5-39484009bdff.png)

只有在使用 Vue 的开发模式时，Vue 开发者工具才能正常工作。默认情况下，未压缩版本的 Vue 已启用开发模式。然而，如果您使用的是代码的生产版本，则可以通过在代码中将`devtools`变量设置为`true`来启用开发工具：

```js
Vue.config.devtools = true
```

在整本书中，我们一直使用的是 Vue 的开发版本，所以开发工具应该可以与我们开发的所有三个单页应用程序一起使用。打开 Dropbox 示例并打开 Vue 开发者工具。

# 检查 Vue 组件的数据和计算值

Vue 开发者工具提供了对页面上使用的组件的很好的概述。您还可以深入到组件中，并预览该特定实例中使用的数据。这非常适合在任何给定时间检查页面上每个组件的属性。

例如，如果我们检查 Dropbox 应用程序并导航到组件选项卡，我们可以看到<Root> Vue 实例和<DropboxViewer>组件。点击这个将显示组件的所有数据属性 - 以及任何计算属性。这样我们就可以验证结构是否正确构建，以及计算路径属性：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/fd41fc73-2502-42c2-b4ec-218588b0bd34.png)

深入研究每个组件，我们可以访问单个数据对象和计算属性。

使用 Vue 开发者工具来检查应用程序是一种更高效的验证数据的方式，因为它可以避免使用多个`console.log()`语句。

# 查看 Vuex 的 mutations 和时间旅行

导航到下一个选项卡 Vuex，可以实时观察存储变化的发生。每次发生变化时，左侧面板中都会创建一行。这个元素允许我们查看发送的数据以及数据提交之前和之后的 Vuex 存储的样子。

它还提供了几个选项来还原、提交和时间旅行到任何点。加载 Dropbox 应用程序后，左侧面板中立即出现几个结构变化，列出了变化的名称和发生的时间。这是预缓存文件夹的代码。点击每个变化将显示 Vuex 存储状态 - 以及包含的负载的变化。状态显示是在负载发送和变化提交之后。要预览在该变化之前状态的样子，选择前面的选项：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ea5f9e57-a1da-4dbb-bb62-aa744d97cc83.png)

在每个条目旁边，您会注意到三个符号，允许您执行几个操作并直接在浏览器中改变存储：

+   **提交此变化**：这允许您提交到该点的所有数据。这将从开发工具中*删除*所有的变化，并将基本状态更新到此点。如果有多个变化发生，您希望跟踪它们，这将非常方便。

+   **撤销此突变**：这将撤销该突变和此点之后的所有突变。这样可以让你一遍又一遍地执行相同的操作，而无需刷新或丢失当前位置。例如，在我们的商店应用程序中将产品添加到购物篮时，会发生突变。使用此功能可以让你从购物篮中删除产品并撤销任何后续的突变，而无需离开产品页面。

+   **时间旅行到此状态**：这允许您预览应用程序和该特定突变时的状态，而不会撤销所选点之后发生的任何突变。

突变选项卡还允许您在左侧面板顶部提交或撤销所有突变。在右侧面板中，您还可以导入和导出存储状态的 JSON 编码版本。当您想要重新测试多种情况和实例而无需重现多个步骤时，这非常方便。

# 预览事件数据

Vue 开发者工具的事件选项卡与 Vuex 选项卡的工作方式类似，允许您检查应用程序中发出的任何事件。我们的 Dropbox 应用程序不使用事件，因此打开我们在本书的第二章“显示、循环、搜索和过滤数据”中创建的 people-filtering 应用程序，以及本书的第三章“优化我们的应用程序并使用组件显示数据”。

更改此应用程序中的过滤器会在每次更新过滤器类型时发出一个事件，以及过滤器查询：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/f7219298-cb16-4f17-9c40-750c9b9eeb1b.png)

左侧面板再次列出了事件的名称和发生的时间。右侧面板包含有关事件的信息，包括其组件来源和有效负载。这些数据可以确保事件数据与您预期的一样，并且如果不是，可以帮助您找到触发事件的位置。

Vue 开发工具是非常宝贵的，特别是当你的 JavaScript 应用程序变得越来越大和复杂时。打开我们开发的商店 SPA，检查各个组件和 Vuex 数据，了解这个工具如何帮助你创建只提交所需的突变并发出所需的事件的应用程序。

# 测试你的 SPA

大多数 Vue 测试套件都围绕着具备命令行知识并使用**CLI**（**命令行界面**）创建 Vue 应用程序。除了使用前端兼容的 JavaScript 创建应用程序外，Vue 还有一个 CLI，允许您使用基于组件的文件创建应用程序。这些文件具有`.vue`扩展名，包含模板 HTML 以及组件所需的 JavaScript。它们还允许您创建作用域 CSS-仅适用于该组件的样式。如果选择使用 CLI 创建应用程序，则本书中学到的所有理论和大部分实践知识都可以轻松移植过来。

# 命令行单元测试

除了组件文件，Vue CLI 还允许您更轻松地集成命令行单元测试，例如 Jest、Mocha、Chai 和 TestCafe（[`testcafe.devexpress.com/`](https://testcafe.devexpress.com/)）。例如，TestCafe 允许您指定多个不同的测试，包括检查内容是否存在，点击按钮以测试功能等。一个 TestCafe 测试的示例是检查我们第一个应用程序中的过滤组件是否包含单词*Field*：

```js
test('The filtering contains the word "filter"', async testController => {
  const filterSelector = await new Selector('body > #app > form > label:nth-child(1)');

  await testController.expect(paragraphSelector.innerText).eql('Filter');
});
```

这个测试将返回`true`或`false`。单元测试通常与组件本身一起编写，允许组件在隔离环境中被重用和测试。这样可以确保外部因素对测试结果没有影响。

大多数命令行 JavaScript 测试库都可以与 Vue.js 集成；在 awesome Vue GitHub 存储库（[`github.com/vuejs/awesome-vue#test`](https://github.com/vuejs/awesome-vue#test)）中有一个很棒的列表可用。

# 浏览器自动化

使用命令行单元测试的替代方法是使用测试套件自动化浏览器。这种测试仍然通过命令行触发，但不是直接与 Vue 应用程序集成，而是在浏览器中打开页面并像用户一样与之交互。一个常用的工具是`Nightwatch.js`（[`nightwatchjs.org/`](http://nightwatchjs.org/)）。

您可以使用这个套件来打开您的商店，并与过滤组件或产品列表排序进行交互，并比较结果。这些测试用例使用非正式的英语编写，并不限于与要测试的站点在同一域名或文件网络上。该库也是语言无关的，适用于任何网站，无论它是用什么构建的。

`Nightwatch.js`在他们的网站上给出的示例是打开 Google 并确保`rembrandt van rijn`的谷歌搜索结果的第一个结果是维基百科条目：

```js
module.exports = {
  'Demo test Google' : function (client) {
    client
      .url('http://www.google.com')
      .waitForElementVisible('body', 1000)
      .assert.title('Google')
      .assert.visible('input[type=text]')
      .setValue('input[type=text]', 'rembrandt van rijn')
      .waitForElementVisible('button[name=btnG]', 1000)
      .click('button[name=btnG]')
      .pause(1000)
      .assert.containsText('ol#rso li:first-child',
        'Rembrandt - Wikipedia')
      .end();
  }
};
```

Nightwatch 的替代品是 Selenium（[`www.seleniumhq.org/`](http://www.seleniumhq.org/)）。 Selenium 的优点是有一个 Firefox 扩展，可以让您可视化地创建测试和命令。

测试，特别是对于大型应用程序来说，是至关重要的，尤其是在将应用程序部署到开发环境时。无论您选择单元测试还是浏览器自动化，都有大量关于这个主题的文章和书籍可供参考。

# 摘要

到目前为止，我们创建了一个模拟商店。使用 Shopify CSV 文件中的真实数据，我们创建了一个允许单独查看产品的应用程序。我们还创建了一个可以进行过滤和排序的类别列表页面，使用户可以找到他们想要的特定产品。为了完善体验，我们构建了一个可编辑的购物篮、结账和订单确认屏幕。在本章中，我们介绍了 Vue 开发工具的使用，以及如何构建测试。


# 第十三章：过渡和动画

本章将介绍以下内容：

+   与 animate.css 等第三方 CSS 动画库集成

+   添加自定义的过渡类

+   使用 JavaScript 而不是 CSS 进行动画处理

+   在初始渲染上进行过渡

+   元素之间的过渡

+   在过渡中，在进入阶段之前让元素离开

+   为列表中的元素添加进入和离开过渡

+   在列表中移动的元素进行过渡

+   对组件的状态进行动画处理

+   将可重用的过渡打包到组件中

+   动态过渡

# 介绍

本章包含与过渡和动画相关的示例。Vue 具有用于处理元素进入或离开场景的过渡的标签：<transition>和<transition-group>。您将学习如何使用它们，以便为您的客户提供更好的用户体验。

Vue 过渡非常强大，因为它们是完全可定制的，并且可以轻松地结合 JavaScript 和 CSS 样式，同时具有非常直观的默认值，这样您就可以在不需要所有花哨效果的情况下编写更少的代码。

即使没有过渡标签，您也可以对组件中发生的大部分内容进行动画处理，因为您只需要将状态变量绑定到某些可见属性即可。

最后，一旦您掌握了关于 Vue 过渡和动画的所有知识，您可以轻松地将它们打包到分层组件中，并在整个应用程序中重复使用它们。这不仅使它们功能强大，而且易于使用和维护。

# 与 animate.css 等第三方 CSS 动画库集成

图形界面不仅需要可用性和易于理解，还应提供可负担性和愉悦性。通过提供过渡效果，可以以有趣的方式提供网站的工作方式的线索，这对于帮助很大。在这个示例中，我们将介绍如何在应用程序中使用 CSS 库。

# 准备工作

在开始之前，您可以查看[`daneden.github.io/animate.css/`](https://daneden.github.io/animate.css/)，如图所示，以了解可用的动画效果，但您实际上不需要任何特殊的知识来继续：

！[](assets/f9ba4864-e66a-485c-a49f-10a17ecd5ecc.png)

# 如何操作...

想象一下，您正在创建一个预订出租车的应用程序。我们将创建的界面将简单而有趣。

首先，将`animate.css`库添加到依赖列表中（参考*选择开发环境*教程来了解如何做）。

为了继续，我们需要我们通常的包装器：

```js
<div id="app"> 
</div>
```

在其中，我们将放置一个按钮来叫出租车：

```js
<button @click="taxiCalled = true"> 
  Call a cab 
</button>
```

您已经可以看出我们将使用`taxiCalled`变量来跟踪按钮是否已被按下

让我们添加一个表情符号，以向用户确认出租车已被叫到：

```js
<p v-if="taxiCalled"></p>
```

此时，我们可以添加一些 JavaScript 代码：

```js
new Vue({ 
  el: '#app', 
  data: { 
    taxiCalled: false 
  } 
})
```

运行应用程序，当您按下按钮时，您将立即看到出租车出现。我们是一家很酷的出租车公司，所以让我们让出租车通过过渡来到我们这里：

```js
<transition  
  enter-active-class="animated slideInRight"> 
  <p v-if="taxiCalled"></p> 
</transition>
```

现在运行您的应用程序；如果您叫出租车，它将从右侧滑动到您这里：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/888029b7-74d1-4c9a-8bff-f82c8f721b3c.png)

出租车将从右向左滑动，如图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/d0e494f6-2f43-401d-a551-cea5cfa6aebc.png)

# 它是如何工作的...

每个过渡应用四个类。两个类应用于元素进入*场景*时，另外两个类应用于元素离开时：

| **名称** | **应用于** | **移除于** |
| --- | --- | --- |
| `v-enter` | 元素插入之前 | 一帧后 |
| `v-enter-active` | 元素插入之前 | 过渡结束时 |
| `v-enter-to` | 一帧后 | 过渡结束时 |
| `v-leave` | 过渡开始 | 一帧后 |
| `v-leave-active` | 过渡开始 | 过渡结束时 |
| `v-leave-to` | 一帧后 | 过渡结束时 |

在这里，初始的*v*代表您的过渡名称。如果您没有指定名称，将使用*v*。

虽然过渡的开始是一个明确定义的瞬间，但过渡的结束对于浏览器来说需要一些工作。例如，如果 CSS 动画循环，动画的持续时间只有一个迭代。此外，这可能会在将来的版本中发生变化，所以请记住这一点。

在我们的情况下，我们希望提供一个第三方的`v-enter-active`，而不是编写我们自己的。问题是，我们的库已经为我们想要使用的动画类（`slideInRight`）命名为不同的名称。由于我们无法更改类的名称，我们告诉 Vue 使用`slideInRight`而不是寻找`v-enter-active`类。

为了做到这一点，我们使用了以下代码：

```js
<transition enter-active-class="animated slideInRight">
```

这意味着我们的`v-enter-active`现在被称为`animated slideInRight`。Vue 将在元素插入之前附加这两个类，并在过渡结束时删除它们。只需注意，animated 是一种带有`animate.css`的辅助类。

# 添加自己的过渡类

如果您的应用程序富含动画，并且希望通过混合和匹配在其他项目中重用您的 CSS 类，那么这就是适合您的示例。您还将了解一种重要的性能动画技术，称为 FLIP（First Last Invert Play）。虽然后一种技术通常由 Vue 自动触发，但我们将手动实现它，以更好地理解其工作原理。

# 准备工作

要完成此示例，您应该了解 CSS 动画和过渡的工作原理。这超出了本书的范围，但您可以在[`css3.bradshawenterprises.com/`](https://daneden.github.io/animate.css/)上找到一个很好的入门指南。这个网站也很棒，因为它会解释何时可以使用动画和过渡。

# 如何操作...

我们将为出租车公司构建一个界面（类似于前面的示例），用户可以通过点击按钮来叫出租车，并在叫出租车时提供一个漂亮的动画反馈。

要编写按钮，请编写以下 HTML 代码：

```js
<div id="app"> 
  <button @click="taxiCalled = true"> 
    Call a cab 
  </button> 
  <p v-if="taxiCalled"></p> 
</div>
```

然后，您可以在 JavaScript 中将`taxiCalled`变量初始化为`false`，如下所示：

```js
new Vue({ 
  el: '#app', 
  data: { 
    taxiCalled: false 
  } 
})
```

此时，我们将在 CSS 中创建自定义过渡：

```js
.slideInRight { 
  transform: translateX(200px); 
} 

.go { 
  transition: all 2s ease-out; 
}
```

将您的汽车表情包装在 Vue 过渡中：

```js
<transition  
  enter-class="slideInRight" 
  enter-active-class="go"> 
  <p v-if="taxiCalled"></p> 
</transition>
```

当您运行代码并点击“叫出租车”按钮时，您将看到一辆出租车停在旁边。

# 工作原理...

当我们点击按钮时，`taxiCalled`变量变为`true`，Vue 会将出租车插入到您的页面中。在实际执行此操作之前，它会读取您在`enter-class`中指定的类（在本例中仅为`slideInRight`），并将其应用于包装元素（带有出租车表情的`<p>`元素）。它还会应用在`enter-class-active`中指定的类（在本例中仅为 go）。

`enter-class`中的类在第一帧后被移除，`enter-class-active`中的类在动画结束时也被移除。

此处创建的动画遵循 FLIP 技术，由四个要点组成：

+   **First (F)**：您将属性保持在动画的第一帧中；在我们的例子中，我们希望出租车从屏幕右侧的某个位置开始。

+   **Last (L)**：你将属性保持在动画的最后一帧中，对于我们的情况来说，就是屏幕左侧的出租车。

+   **Invert (I)**：你反转在第一帧和最后一帧之间注册的属性变化。由于我们的出租车向左移动，在最后一帧中它将位于-200 像素的偏移位置。我们反转这个并设置`slideInRight`类，使得 transform 为`translateX(200px)`，这样出租车出现时将位于+200 像素的偏移位置。

+   **Play (P)**：我们为每个已触摸的属性创建一个过渡效果。在出租车的例子中，我们使用了 transform 属性，因此我们使用`writetransition: all 2s ease-out`来使出租车平滑过渡。

Vue 在内部自动使用这种技术来使得在`<transition-group>`标签内的过渡效果正常工作。关于这一点，我们将在*为列表中的元素添加进入和离开过渡效果*的食谱中详细介绍。

# 使用 JavaScript 而不是 CSS 进行动画

有一个普遍的误解，即使用 JavaScript 进行动画会更慢，而动画应该在 CSS 中完成。事实是，如果使用正确，JavaScript 中的动画可以具有相似或更好的性能。在这个食谱中，我们将使用简单但强大的 Velocity.js（[`velocityjs.org/`](http://velocityjs.org/)）库创建一个动画：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ba4a4bef-77a9-4d77-9b99-92d7dcc8a914.png)

# 准备工作

这个食谱假设你对 Velocity 库没有任何了解，但假设你对 CSS 或 JavaScript 库（如 jQuery）中的动画非常熟悉。如果你从未见过 CSS 动画并且想要快速入门，只需完成前两个食谱，你就能跟上。

# 如何实现...

我们仍在寻找一个完美的过渡效果，用于等待出租车时娱乐我们的客户（与前一个食谱中相同）。我们有一个按钮来呼叫出租车，当我们预订时会出现一个小的出租车表情符号。

在任何其他操作之前，将 Velocity 库作为项目的依赖项添加进来--[`cdnjs.cloudflare.com/ajax/libs/velocity/1.2.3/velocity.min.js`](http://velocityjs.org/)。

这是创建界面框架的 HTML 代码：

```js
<div id="app"> 
  <button @click="taxiCalled = true"> 
    Call a cab 
  </button> 
  <p v-if="taxiCalled"></p> 
</div>
```

我们的 Vue 模型非常简单，只包含一个`taxiCalled`变量：

```js
new Vue({ 
  el: '#app', 
  data: { 
    taxiCalled: false 
  } 
})
```

通过将小出租车包装在 Vue 过渡中来创建动画：

```js
<transition 
  @enter="enter" 
  :css="false" 
> 
<p v-if="taxiCalled"></p> 
</transition>
```

当按下按钮插入出租车表情符号时，将调用 enter 方法。

enter 方法，您需要将其添加到 Vue 实例中，如下所示：

```js
methods: { 
    enter (el) { 
      Velocity(el,  
      { opacity: [1, 0], translateX: ["0px", "200px"] }, 
      { duration: 2000, easing: "ease-out" }) 
    } 
  }
```

运行代码并按下按钮预订您的出租车！

# 它是如何工作的...

正如你可能已经注意到的，你的代码中没有 CSS。动画完全由 JavaScript 驱动。让我们稍微解析一下我们的 Vue 过渡：

```js
<transition 
  @enter="enter" 
  :css="false" 
> 
  <p v-if="taxiCalled"></p> 
</transition>
```

虽然这仍然是一个可以使用 CSS 的过渡，但我们想告诉 Vue 关闭 CSS 并节省宝贵的 CPU 周期，通过设置`:css="false"`。这将使 Vue 跳过与 CSS 动画相关的所有代码，并防止 CSS 干扰我们纯粹的 JavaScript 动画。

多汁的部分在`@enter="enter"`这一部分。我们将触发元素插入时的钩子绑定到`enter`方法上。方法本身如下：

```js
enter (el) { 
  Velocity(el,  
    { opacity: [1, 0], translateX: ["0px", "200px"] }, 
    { duration: 2000, easing: "ease-out" }
  ) 
}
```

在这里，我们调用了 Velocity 库。`el`参数由 Vue 免费传递，并且它指的是被插入的元素（在我们的例子中，是包含汽车表情的`<p>`元素）。

Velocity 函数的语法如下所示：

```js
Velocity( elementToAnimate, propertiesToAnimate, [options] )
```

还有其他语法可能，但我们将坚持使用这种语法。

在调用此函数时，我们将段落元素作为第一个参数传递；然后我们说不透明度应该从 0 变为 1，并且同时，元素应该从 x 轴上的起始位置 200 像素移动到其原点。作为选项，我们指定动画持续时间为两秒，并且我们希望在接近结束时缓和动画。

我认为一切都很清楚，除了我们如何传递`opacity`和`translateX`参数。

这就是 Velocity 所谓的**强制喂食**--我们告诉 Velocity 不透明度应该从 0 开始到 1 结束。同样，我们告诉 Velocity`translateX`属性应该从 200 像素开始，结束于 0 像素。

通常情况下，我们可以避免传递数组来指定属性的初始值；Velocity 会计算如何过渡。

例如，我们可以有以下 CSS 类：

```js
p { 
  opacity: 0; 
}
```

如果我们将 Velocity 调用重写如下：

```js
Velocity(el,  
  { opacity: 1 } 
)
```

汽车将慢慢出现。Velocity 查询了元素的初始值，然后将其过渡到 1。这种方法的问题是，由于涉及对 DOM 的查询，某些动画可能会变慢，特别是当您有很多并发动画时。

我们可以通过使用 begin 选项来获得与强制喂食相同的效果，如下所示：

```js
Velocity(el,  
  { opacity: 1 }, 
  { begin: () => { el.style.opacity = 0 } } 
)
```

这将在动画开始之前（因此在元素插入之前）将不透明度设置为零。这将有助于在较慢的浏览器中，强制显示仍然会在将其完全移到右侧并开始动画之前显示一闪而过的汽车。

JavaScript 动画的可能钩子在下表中总结：

| **属性** | **描述** |
| --- | --- |
| `@before-enter` | 在元素插入之前调用此函数。 |
| `@enter` | 当元素插入时调用此函数。 |
| `@after-enter` | 当元素插入并且动画完成时调用此函数。 |
| `@enter-cancelled` | 当动画仍在进行中但元素必须离开时调用此函数。如果使用 Velocity，可以执行类似于`Velocity(el, "stop")`的操作。 |
| `@before-leave` | 在触发离开函数之前调用此函数。 |
| `@leave` | 当元素离开时调用此函数。 |
| `@after-leave` | 当元素离开页面时调用此函数。 |
| `@leave-cancelled` | 在离开调用完成之前，如果必须插入元素，则调用此函数。仅适用于 v-show。 |

请记住，这些钩子对于任何库都有效，不仅仅适用于 Velocity。

# 还有更多...

我们可以尝试使用这个界面来实现一个取消按钮。如果用户错误地预订了出租车，点击取消按钮将删除预订，并且通过小的出租车表情消失来表明。

首先，让我们添加一个取消按钮：

```js
<button @click="taxiCalled = false">
  Cancel
</button>
```

这很容易；现在我们添加离开过渡效果：

```js
<transition 
  @enter="enter" 
  @leave="leave" 
  :css="false" 
> 
  <p v-if="taxiCalled"></p> 
</transition>
```

这将引导我们到离开方法：

```js
leave (el) { 
  Velocity(el, 
    { opacity: [0, 1], 'font-size': ['0.1em', '1em'] }, 
    { duration: 200}) 
}
```

我们正在做的是使表情符号消失并缩小。

如果您尝试运行代码，您将遇到一些问题。

当您点击取消按钮时，应该发生的是离开动画应该开始，出租车应该变小并最终消失。相反，什么都不会发生，出租车会突然消失。

取消动画无法按计划播放的原因是因为动画是用 JavaScript 编写的，而不是 CSS，Vue 无法判断动画何时完成。特别是，发生的情况是 Vue 认为离开动画在开始之前就已经完成了。这就是我们的汽车消失的原因。

关键在于第二个参数。每个钩子都调用一个带有两个参数的函数。我们已经看到了第一个参数`el`，它是动画的主体。第二个参数是一个回调函数，当调用时，告诉 Vue 动画已经完成。

我们将利用 Velocity 有一个名为`complete`的选项，它期望在动画（从 Velocity 的角度）完成时调用一个函数。

让我们使用这些新信息重写我们的代码：

```js
leave (el, done) { 
  Velocity(el, 
  { opacity: [0, 1], 'font-size': ['0.1em', '1em'] }, 
  { duration: 200 }) 
}
```

向我们的函数添加`done`参数，让 Vue 知道我们希望在动画完成时调用回调函数。我们不需要显式使用回调函数，因为 Vue 会自动找到它，但是由于依赖默认行为总是一个坏主意（如果它们没有记录，它们可能会改变），让我们在动画完成时调用`done`函数：

```js
leave (el, done) { 
  Velocity(el, 
  { opacity: [0, 1], 'font-size': ['0.1em', '1em'] }, 
  { duration: 200, complete: done }) 
}
```

运行代码并按下取消按钮来取消您的出租车！

# 在初始渲染上进行过渡

通过使用`appear`关键字，我们可以在元素首次加载时为其添加过渡效果。这有助于提高用户体验，因为它给人一种页面更具响应性和加载速度更快的印象，尤其是当应用于多个元素时。

# 准备工作

这个示例不假设任何特定的知识，但如果您至少完成了*使用 CSS 过渡为您的应用程序增添一些乐趣*示例，那么这将是小菜一碟。

# 操作步骤...

我们将建立一个关于美国演员 Fill Murray 的页面；不，不是 Bill Murray。您可以在[`www.fillmurray.com`](https://cdnjs.cloudflare.com/ajax/libs/velocity/1.2.3/velocity.min.js)找到关于他的更多信息。我们将使用这个网站的图片来填充我们关于他的页面。

在我们的 HTML 中，让我们写一个标题作为页面的标题：

```js
<h1> 
  The Fill Murray Page 
</h1>
```

在标题之后，我们将放置我们的 Vue 应用程序：

```js
<div id="app"> 
  <img src="https://fillmurray.com/50/70"> 
  <p> 
    The internet was missing the ability to 
    provide custom-sized placeholder images of Bill Murray. 
    Now it can. 
  </p> 
</div>
```

在浏览器中呈现时，将显示如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/6132613a-c762-478c-9751-3dd4d3e38999.png)

我们的页面现在非常简单。我们希望 Fill Murray 的图片淡入。我们必须将其包装在一个过渡中：

```js
<transition appear> 
  <img src="https://fillmurray.com/50/70"> 
</transition>
```

以下是 CSS 类：

```js
img { 
  float: left; 
  padding: 5px 
} 
.v-enter { 
  opacity: 0 
} 
.v-enter-active { 
  transition: opacity 2s 
}
```

现在运行我们的页面将使图片慢慢出现，但也会移动文本。为了修复这个问题，我们必须提前指定图片的大小：

```js
<transition appear> 
  <img src="https://fillmurray.com/50/70" width="50" height="70"> 
</transition>
```

这样，我们的浏览器将为即将出现的图片预留一些空间。

# 工作原理...

`transition`标签中的`appear`指令将使组件在首次出现时带有关联的过渡效果（如果找到）。

在组件的第一次渲染中，有很多可能的方法来指定一个过渡。在所有情况下，必须指定`appear`指令。

当这个指令存在时，Vue 将首先寻找 JavaScript 钩子或在标签中指定的 CSS 类：

```js
<transition 
  appear 
  @before-appear="customBeforeAppearHook" 
  @appear="customAppearHook" 
  @after-appear="customAfterAppearHook" 
  appear-class="custom-appear-class" 
  appear-active-class="custom-appear-active-class" 
> 
  <p>My element</p> 
</transition>
```

之后，如果指定了一个名称，Vue 将会寻找该元素的入场过渡：

```js
<transition appear name="myTransition"> 
  <p>My element</p> 
</transition>
```

上述代码将寻找以下命名的类：

```js
.myTransition-enter {...} 
.myTransition-enter-active {...}
```

如果其他方法都失败了，Vue 将会寻找元素插入的默认 CSS 类（`v-enter`和`v-enter-active`）。顺便说一句，这就是我们在这个示例中所做的。

依赖这些默认值并不是一个好的实践；在这里，我们只是作为演示而这样做。你应该总是给你的过渡命名。

也许值得一提的是，为什么我们必须为图像添加宽度和高度。原因是当我们在 HTML 中指定一个图像 URL 时，浏览器不知道图像的大小，所以默认情况下不会为其保留任何空间。只有通过提前指定图像的大小，浏览器才能在图像加载之前正确地组合页面。

# 元素之间的过渡

网页上的每个东西都是一个元素。通过 Vue 的`v-if`和`v-show`指令，你可以轻松地使它们出现和消失。通过过渡，你甚至可以轻松地控制它们的出现，并添加魔法效果。本示例将解释如何做到这一点。

# 准备工作

对于这个示例，你应该对 Vue 过渡和 CSS 的工作原理有一些了解。

# 如何做到这一点...

既然我们谈到了魔法，我们将把一只青蛙变成一位公主。变化本身将是一个过渡。

我们将实例化一个按钮，当按下时，它将代表对青蛙的一个吻：

```js
<div id="app"> 
  <button @click="kisses++">Kiss!</button> 
</div>
```

每次按下按钮时，变量 kisses 都会增加。变量将被初始化为零，如下面的代码所示：

```js
new Vue({ 
   el: '#app', 
  data: { 
   kisses: 0 
  } 
})
```

接下来，我们需要青蛙和公主，我们将在按钮之后立即添加它们：

```js
<transition name="fade"> 
  <p v-if="kisses < 3" key="frog">frog</p> 
  <p v-if="kisses >= 3" key="princess">princess</p> 
</transition>
```

淡入淡出过渡的 CSS 代码如下：

```js
.fade-enter-active, .fade-leave-active { 
  transition: opacity .5s 
} 
.fade-enter, .fade-leave-active { 
  opacity: 0 
}
```

为了使其正常工作，我们需要添加一个最后的 CSS 选择器：

```js
p { 
  margin: 0; 
  position: absolute; 
  font-size: 3em; 
}
```

如果你运行应用程序并点击足够多次的吻按钮，你应该会看到你的青蛙变成一位公主：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/3a709d1d-79ed-4bb9-86a8-aeaeeadcaf9a.png)

这个过渡将有一个淡入淡出的效果：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/d17f58dc-50cd-4e11-b234-c4633095a802.png)

青蛙表情符号将变成公主表情符号：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/297edc0a-d809-41d8-9490-b59770387e70.png)

# 它是如何工作的...

当我们写下这两个元素时，我们使用了`key`属性来指定谁是青蛙，谁是公主。这是因为，否则 Vue 优化系统将会启动。它会看到两个元素的内容可以互换，而不必交换元素本身，并且由于元素是相同的，只有内容发生了变化，所以不会发生过渡。

如果我们移除`key`属性，我们可以亲眼看到青蛙和公主会发生变化，但没有任何过渡效果：

```js
<transition name="fade"> 
  <p v-if="kisses < 3">frog</p> 
  <p v-if="kisses >= 3">princess</p> 
</transition>
```

考虑到我们使用了两个不同的元素，如下所示：

```js
<p v-if="kisses < 3" >frog</p> 
<span v-if="kisses >= 3">princess</span>
```

此外，我们相应地修改了`<p>`的 CSS 选择器：

```js
p, span { 
  margin: 0; 
  position: absolute; 
  font-size: 3em; 
  display: block; 
}
```

现在，如果我们再次启动应用程序，一切都可以正常工作，而不需要使用任何`key`属性。

即使在不必要的情况下，使用 key 通常也是推荐的，就像前面的情况一样。这尤其适用于项目具有不同的语义含义的情况。这样做的原因有几个。主要原因是，当多个人在同一行代码上工作时，修改`key`属性不会像将`span`元素切换回`p`元素那样容易破坏应用程序，这会破坏我们刚刚看到的过渡效果。

# 还有更多...

在这里，我们涵盖了前面示例的两个子情况：在多个元素之间切换和绑定`key`属性。

# 在多个元素之间进行过渡

我们可以按照简单的方式扩展我们刚刚完成的示例。

假设如果我们亲吻公主太多次，她会变成圣诞老人，这可能会或可能不会吸引人，这取决于你的年龄。

首先，我们添加第三个元素：

```js
<transition name="fade"> 
  <p v-if="kisses < 3" key="frog">frog</p> 
  <p v-else-if="kisses >= 3 && kisses <= 5" key="princess">princess</p> 
  <p v-else key="santa">santa</p> 
</transition>
```

我们可以立即启动应用程序，当我们亲吻公主/青蛙超过五次时，圣诞老人将以相同的淡入淡出过渡效果出现：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ee62f5c3-adb1-4d2e-819b-cfe0888084b8.png)

使用这种设置，我们在使用第一个和第二个元素之间使用相同的过渡时受到限制。

在*动态过渡*的示例中，有一个解决方法。

# 动态设置 key 属性

如果我们已经有一些可用的数据，我们不必为所有元素编写 key。我们可以以以下方式编写相同的应用程序，但不重复元素：

```js
<transition name="fade">
  <p :key="transformation">{{emoji}}{{transformation}}</p>
</transition>
```

当然，这意味着我们必须根据亲吻的次数为`transformation`和`emoji`变量提供一个合理的值。

为了做到这一点，我们将把它们与计算属性绑定起来：

```js
computed: { 
  transformation () { 
    if (this.kisses < 3) { 
      return 'frog' 
    } 
    if (this.kisses >= 3 && this.kisses <= 5) { 
      return 'princess' 
    } 
    if (this.kisses > 5) { 
      return 'santa' 
    } 
  }, 
  emoji () { 
    switch (this.transformation) { 
      case 'frog': return '' 
      case 'princess': return '' 
      case 'santa': return '' 
    } 
  } 
}
```

我们在模板中牺牲了一些复杂性，换取了 Vue 实例中更多的逻辑。如果我们预计将来会有更复杂的逻辑或者转换数量增加，这可能是有益的。

# 在过渡中让元素在进入阶段之前离开

在*元素之间过渡*的示例中，我们探讨了如何在两个元素之间进行过渡。Vue 的默认行为是在第一个元素离开的同时开始进入元素的过渡；这并不总是理想的。

您将在本示例中了解到这个重要的特殊情况以及如何解决它。

# 准备工作

这个示例是在两个元素之间的过渡的基础上构建的，解决了一个特定的问题。如果您不知道我们在谈论什么，返回上一个示例，您将很快跟上。

# 如何做...

首先，如果您还没有遇到这个问题，您将看到问题。接下来，我们将看到 Vue 为我们提供的解决方案。

# 两个元素的问题

让我们在我们的网站上创建一个轮播效果。用户一次只能查看一个产品，然后他将滑动到下一个产品。要滑动到下一个产品，用户需要点击一个按钮。

首先，我们需要在 Vue 实例中有我们的产品列表：

```js
new Vue({ 
  el: '#app', 
  data: { 
    product: 0, 
    products: ['umbrella', 'computer', 'ball', 'camera'] 
  } 
})
```

在我们的 HTML 中，我们只需要一个按钮和一个元素的视图：

```js
<div id="app"> 
  <button @click="product++">next</button> 
  <transition name="slide"> 
    <p :key="products[product % 4]">{{products[product % 4]}}</p> 
  </transition> 
</div>
```

模 4（product % 4）只是因为我们希望在产品列表结束时重新开始。

为了设置我们的滑动过渡，我们需要以下规则：

```js
.slide-enter-active, .slide-leave-active { 
  transition: transform .5s 
} 
.slide-enter { 
  transform: translateX(300px) 
} 
.slide-leave-active { 
  transform: translateX(-300px); 
}
```

此外，为了使一切看起来好看，我们最后完成了以下内容：

```js
p { 
  position: absolute; 
  margin: 0; 
  font-size: 3em; 
}
```

如果现在运行代码，您将看到一个漂亮的轮播图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/27675ea7-0d13-48b1-83d1-91270017df29.png)

现在，让我们尝试从最后一个规则中删除`position: absolute`：

```js
p { 
  margin: 0; 
  font-size: 3em; 
}
```

如果您现在尝试您的代码，您将看到产品之间的奇怪跳动：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/90d782ed-fe42-4226-885d-4d370ff4d49c.png)

这是我们试图解决的问题。第二个过渡在第一个产品离开之前就开始了。如果定位不是绝对的，我们会看到一些奇怪的效果。

# 过渡模式

为了解决这个问题，我们将改变过渡模式。让我们修改`<transition>`的代码：

```js
<transition name="slide" mode="out-in"> 
  <p :key="products[product%4]">{{products[product%4]}}</p> 
</transition>
```

现在运行您的程序，您将看到产品在滑入屏幕之前需要更长的时间。它们在进入之前等待上一个项目离开。

# 工作原理...

总之，您有两种不同的方法来管理 Vue 组件之间的过渡。默认方式是同时开始“in”过渡和“out”过渡。我们可以通过以下方式明确表示：

```js
<transition mode="in-out"> 
  <!-- elements --> 
</transition>
```

我们可以通过等待“out”部分完成后再开始“in”动画来改变这种默认行为。我们通过以下方式实现了这一点：

```js
<transition mode="out-in"> 
  <!-- elements --> 
</transition>
```

前者在元素具有绝对样式位置时很有用，而后者在我们真正需要等待在页面上放置更多内容之前有一个清晰的方法时更相关。

绝对定位不会在意元素之间的重叠，因为它们不遵循页面的流动。另一方面，静态定位将在第一个元素之后追加第二个元素，如果两个元素同时显示，则过渡会变得尴尬。

# 为列表中的元素添加进入和离开过渡

在这里，我们将尝试添加一种视觉方式来暗示列表中的元素是添加还是删除。这可以为用户体验增添很多，因为您有机会向用户建议为什么添加或删除元素。

# 准备工作

对 CSS 和过渡有一些了解会有所帮助。如果您觉得有必要，只需浏览本章中的其他示例。

# 如何做...

我们将建立一个学习编程的教学大纲。当我们完成一个主题时，我们会感到宽慰，并希望通过让主题从教学大纲中飘走来将这种感觉融入我们的应用程序中。

列表的数据将在我们的 Vue 实例中：

```js
new Vue({ 
  el: '#app', 
  data: { 
    syllabus: [ 
      'HTML', 
      'CSS', 
      'Scratch', 
      'JavaScript', 
      'Python' 
    ] 
  } 
})
```

列表将在我们的 HTML 中打印出以下代码：

```js
<div id="app"> 
  <h3>Syllabus</h3> 
  <ul> 
    <li v-for="topic in syllabus"> 
      {{topic}} 
    </li> 
  </ul> 
</div>
```

当我们按下按钮时，我们希望主题从列表中消失。为了实现这一点，我们需要修改我们已经编写的代码。

首先，在每个主题之前添加一个“完成”按钮：

```js
<li v-for="topic in syllabus"> 
  <button @click="completed(topic)">Done</button>{{topic}} 
</li>
```

在这里，completed 方法将如下所示：

```js
methods: { 
  completed (topic) { 
    let index = this.syllabus.indexOf(topic) 
    this.syllabus.splice(index, 1) 
  } 
}
```

现在运行代码将显示一个简单的应用程序，用于勾选我们已经学习过的主题。不过，我们想要的是一种让我们感到宽慰的动画。

为此，我们需要编辑我们列表的容器。我们删除`<ul>`标签，并告诉`<transition-group>`编译为`<ul>`标签：

```js
<transition-group tag="ul"> 
  <li v-for="topic in syllabus" :key="topic"> 
    <button @click="completed(topic)">Done</button>{{topic}} 
  </li> 
</transition-group>
```

请注意，我们还根据主题为每个列表元素添加了一个键。我们需要做的最后一件事是将过渡规则添加到我们的 CSS 中：

```js
.v-leave-active { 
  transition: all 1s; 
  opacity: 0; 
  transform: translateY(-30px); 
}
```

现在，主题将在点击“完成”按钮时以过渡方式消失，如下所示：

！[](assets/1dc697d3-26c5-4957-86c6-2ed79cc3966b.png)

# 它是如何工作的...

`<transition-group>`标签表示一组元素的容器，这些元素将同时显示。默认情况下，它表示`<span>`标签，但通过将标签属性设置为`ul`，我们使其表示无序列表。

列表中的每个元素必须具有唯一的键，否则转换将无法工作。Vue 将负责对每个进入或离开的元素应用转换。

# 在列表中移动的过渡元素

在这个教程中，您将构建一个元素列表，根据列表的变化而移动。当您想告诉用户某些内容已经改变并且列表已相应更新时，这种特定的动画是有用的。它还将帮助用户识别插入元素的位置。

# 准备工作

这个教程有点高级；如果您对 Vue 中的过渡不是很熟悉，我建议您先完成本章中的一些教程。如果您可以轻松完成*为列表元素添加进入和离开过渡*教程，那就可以继续了。

# 如何做...

您将构建一个小游戏--一个公交车站模拟器！

每当一辆公交车--由其表情符号表示--离开车站时，所有其他公交车都会稍微前进以占据它的位置。每辆公交车都由一个数字标识，您可以从 Vue 实例数据中看到：

```js
new Vue({ 
  el: '#app', 
  data: { 
    buses: [1,2,3,4,5], 
    nextBus: 6 
  } 
})
```

每当新的公交车到达时，它将被分配一个递增的编号。我们希望每两秒钟有一辆新的公交车离开或到达。我们可以通过在组件挂载到屏幕时挂接一个计时器来实现这一点。在数据之后，立即编写以下内容：

```js
mounted () { 
  setInterval(() => { 
    const headOrTail = () => Math.random() > 0.5 
    if (headOrTail()) { 
      this.buses.push(this.nextBus) 
      this.nextBus += 1 
    } else { 
      this.buses.splice(0, 1) 
    } 
  }, 2000) 
}
```

我们应用的 HTML 将如下所示：

```js
<div id="app"> 
  <h3>Bus station simulator</h3> 
  <transition-group tag="p" name="station"> 
    <span v-for="bus in buses" :key="bus"></span> 
  </transition-group> 
</div>
```

为了让公交车四处移动，我们需要在前缀站下指定一些 CSS 规则：

```js
.station-leave-active, .station-enter-active { 
  transition: all 2s; 
  position: absolute; 
} 

.station-leave-to { 
  opacity: 0; 
  transform: translateX(-30px); 
} 

.station-enter { 
  opacity: 0; 
  transform: translateX(30px); 
} 

.station-move { 
  transition: 2s; 
} 

span { 
  display: inline-block; 
  margin: 3px; 
}
```

现在启动应用将导致一个有序的公交车队列，每两秒钟有一辆公交车离开或到达：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/c4f025b1-b825-45e3-8ab4-9f362737ccd2.png)

# 工作原理...

我们应用的核心是`<transition-group>`标签。它管理所有通过它们的键标识的公交车：

```js
<transition-group tag="p" name="station"> 
  <span v-for="bus in buses" :key="bus"></span> 
</transition-group>
```

每当一辆公交车进入或离开场景时，Vue 将自动触发 FLIP 动画（参见*添加自己的过渡类*教程）。

为了更好地理解，假设我们有公交车[1, 2, 3]，公交车 1 离开了。接下来发生的是，在动画实际开始之前，将记住第一辆公交车的`<span>`元素的属性。因此，我们可以检索到描述属性的以下对象：

```js
{ 
  bottom:110.4375 
  height:26 
  left:11 
  right:27 
  top:84.4375 
  width:16 
}
```

Vue 对`<transition-group>`标签内的所有元素都这样做。

之后，`station-leave-active`类将应用于第一辆公交车。让我们简要回顾一下规则是什么：

```js
.station-leave-active, .station-enter-active { 
  transition: all 2s; 
  position: absolute; 
}
```

我们注意到位置变为绝对定位。这意味着元素从页面的正常流程中移除。这又意味着所有在它后面的公交车将突然移动填补留下的空间。Vue 在这个阶段记录所有公交车的属性，这被认为是动画的最终帧。这个帧实际上并不是一个真正显示的帧；它只是用来计算元素的最终位置的抽象：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/43cd7f74-3133-418b-bd7b-48893eb924a4.png)

Vue 将计算最终帧和起始帧之间的差异，并将应用样式，使公交车出现在初始帧，即使它们实际上并不在那里。这些样式将在一帧后被移除。公交车缓慢爬向它们的最终位置，而不是立即移动到它们的新位置，原因是它们是`span`元素，我们指定了任何变换样式（Vue 用来伪造它们位置一帧的样式）必须过渡两秒：

```js
.station-move { 
  transition: 2s; 
}
```

换句话说，在第-1 帧，三辆公交车都在原位，并记录了它们的位置。

在第 0 帧，第一辆公交车从页面流中移除，其他公交车立即移动到它的后面。在同一帧中，Vue 记录它们的新位置，并应用一个变换，将公交车移回到它们在第-1 帧的位置，从视觉上看就好像没有人移动过。

在第 1 帧，变换被移除，但由于我们有一个过渡，公交车将缓慢移动到它们的最终位置。

# 动画化组件的状态

在计算机中，一切都是数字。在 Vue 中，一切都是数字的东西都可以以某种方式进行动画。在这个配方中，您将控制一个弹跳球，它将通过缓动动画平稳地定位自己。

# 准备工作

完成这个配方，您至少需要对 JavaScript 有一定的了解。JavaScript 的技术细节超出了本书的范围，但我会在*它是如何工作的...*部分为您解释代码，所以不要太担心。

# 如何做...

在我们的 HTML 中，我们只会添加两个元素：一个输入框，我们将在其中输入我们的弹跳球的期望位置，以及球本身：

```js
<div id="app"> 
  <input type="number"> 
  <div class="ball"></div> 
</div>
```

为了正确渲染小球，写下这个 CSS 规则，它将出现在屏幕上：

```js
.ball { 
  width: 3em; 
  height: 3em; 
  background-color: red; 
  border-radius: 50%; 
  position: absolute; 
  left: 10em; 
}
```

我们想要控制球的*Y*位置。为此，我们将绑定球的`top`属性：

```js
<div id="app"> 
  <input type="number"> 
  <div class="ball" :style="'top: ' + height + 'em'"></div> 
</div>
```

高度将成为我们 Vue 实例模型的一部分：

```js
new Vue({ 
   el: '#app', 
   data: { 
     height: 0 
   } 
})
```

现在，由于我们希望每当`enteredHeight`更改时，球在新位置上进行动画，一个想法是绑定输入元素的`@change`事件：

```js
<div id="app"> 
  <input type="number" @input="move"> 
  <div class="ball" :style="'top: ' + height + 'em'"></div> 
</div>
```

move 方法将负责将球的当前高度缓慢过渡到指定值。

在执行此操作之前，您将将**Tween.js**库添加为依赖项。官方存储库位于[`github.com/tweenjs/tween.js`](https://github.com/tweenjs/tween.js)。如果您在使用 JSFiddle，可以添加 README.md 页面中指定的 CDN 链接。

在添加库之后添加 move 方法，就像这样：

```js
methods: { 
  move (event) { 
    const newHeight = Number(event.target.value) 
    const _this = this 
    const animate = (time) => { 
      requestAnimationFrame(animate) 
      TWEEN.update(time) 
    } 
    new TWEEN.Tween({ H: this.height }) 
      .easing(TWEEN.Easing.Bounce.Out) 
      .to({ H: newHeight }, 1000) 
      .onUpdate(function () { 
        _this.height = this.H 
      }) 
      .start() 
    animate() 
  } 
}
```

尝试启动应用程序，看到球在您编辑其高度时弹跳：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/1f7dd650-3963-4f71-9d27-2c6ebdc95ef9.png)

当我们改变高度时，球的位置也会改变：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/069a6b5b-0417-4316-b6b7-d755712488be.png)

# 它是如何工作的...

这里的一般原则是，您有一个元素或组件的状态。当状态是数字性质时，您可以根据特定的曲线或加速度从一个值“tween”（在之间）到另一个值。

让我们来分解代码，好吗？

我们要做的第一件事是将指定的新高度保存到`newHeight`变量中：

```js
const newHeight = Number(event.target.value)
```

在下一行，我们还将 Vue 实例保存在`_this`辅助变量中：

```js
const _this = this
```

我们这样做的原因一分钟后就会清楚：

```js
const animate = (time) => { 
  requestAnimationFrame(animate) 
  TWEEN.update(time) 
}
```

在前面的代码中，我们将所有的动画包装在一个函数中。这是 Tween.js 库的惯用法，并且确定了我们将用于动画的主循环。如果我们有其他 Tween，这就是触发它们的地方：

```js
new TWEEN.Tween({ H: this.height }) 
  .easing(TWEEN.Easing.Bounce.Out) 
  .to({ H: newHeight }, 1000) 
  .onUpdate(function () { 
    _this.height = this.H 
  }) 
.start()
```

这是对我们库的 API 调用。首先，我们创建一个对象，它将保存状态值的副本，而不是我们组件的状态。通常，在这里，您放置代表状态本身的对象。由于 Vue 的限制（或 Tween.js 的限制），我们使用了一种不同的策略；我们正在动画化状态的副本，并且我们正在为每一帧同步真实状态：

```js
Tween({ H: this.height })
```

第一行将此副本初始化为球的当前实际高度：

```js
easing(TWEEN.Easing.Bounce.Out)
```

我们选择缓动效果来模拟弹跳球：

```js
.to({ H: newHeight }, 1000)
```

这行设置了目标高度和动画应持续的毫秒数：

```js
onUpdate(function () { 
  _this.height = this.H 
})
```

在这里，我们将动画的高度复制回真实的事物。由于此函数将 this 绑定到复制的状态，我们被迫使用 ES5 语法来访问它。这就是为什么我们有一个变量准备好引用 Vue 实例的原因。如果我们使用了 ES6 语法，我们将无法直接获取`H`的值。

# 将可重用的过渡效果打包到组件中

我们可能在网站中有一个重要的过渡效果，我们希望在用户漏斗中重复使用。如果您试图保持代码有序，将过渡效果打包到组件中可能是一个很好的策略。在这个示例中，您将构建一个简单的过渡组件。

# 准备工作

如果您已经通过 Vue 的过渡效果工作过，那么遵循这个示例是有意义的。此外，由于我们正在使用组件，您至少应该对它们有所了解。浏览下一章以了解组件的基础知识。特别是，我们将创建一个功能性组件，其解剖结构在*创建功能性组件*示例中有详细说明。

# 操作步骤...

我们将为新闻门户构建一个特色过渡效果。实际上，我们将使用优秀的 magic 库中的预制过渡效果（[`github.com/miniMAC/magic`](https://github.com/miniMAC/magic)），因此您应该将其添加到项目中作为依赖项。您可以在[`cdnjs.com/libraries/magic`](https://cdnjs.com/libraries/magic)找到 CDN 链接（[转到页面查找链接，不要将其复制为链接](https://github.com/miniMAC/magic)）。

首先，您将构建网站页面，然后构建过渡效果本身。最后，您将只需将过渡效果添加到不同的元素中。

# 构建基本网页

我们的网页将包括两个按钮，每个按钮将显示一个卡片：一个是食谱，另一个是最新的突发新闻：

```js
<div id="app"> 
  <button @click="showRecipe = !showRecipe"> 
    Recipe 
  </button> 
  <button @click="showNews= !showNews"> 
    Breaking News 
  </button> 
  <article v-if="showRecipe" class="card"> 
    <h3> 
      Apple Pie Recipe 
    </h3> 
    <p> 
      Ingredients: apple pie. Procedure: serve hot. 
    </p> 
  </article> 
  <article v-if="showNews" class="card"> 
    <h3> 
      Breaking news 
    </h3> 
    <p> 
      Donald Duck is the new president of the USA. 
    </p> 
  </article> 
</div>
```

由于以下 CSS 规则，卡片将具有其独特的触感：

```js
.card { 
  position: relative; 
  background-color: FloralWhite; 
  width: 9em; 
  height: 9em; 
  margin: 0.5em; 
  padding: 0.5em; 
  font-family: sans-serif; 
  box-shadow: 0px 0px 10px 2px rgba(0,0,0,0.3); 
}
```

JavaScript 部分将是一个非常简单的 Vue 实例：

```js
new Vue({ 
  el: '#app', 
  data: { 
    showRecipe: false, 
    showNews: false 
  } 
})
```

运行此代码将会显示您的网页：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/ed375e27-7280-4136-94b9-add992772c44.png)

# 构建可重用的过渡效果

我们决定我们的网站在显示卡片时将会有一个过渡效果。由于我们打算在网站的所有地方重复使用动画，最好将其打包在一个组件中。

在 Vue 实例之前，我们声明了以下组件：

```js
Vue.component('puff', { 
  functional: true, 
  render: function (createElement, context) { 
    var data = { 
      props: { 
        'enter-active-class': 'magictime puffIn', 
        'leave-active-class': 'magictime puffOut' 
      } 
    } 
    return createElement('transition', data, context.children) 
  } 
})
```

`puffIn`和`puffOut`动画在`magic.css`中定义。

# 在我们网页中使用我们的过渡效果

现在，我们将编辑我们的网页，向卡片中添加`<puff>`组件：

```js
<div id="app"> 
  <button @click="showRecipe = !showRecipe"> 
    Recipe 
  </button> 
  <button @click="showNews = !showNews"> 
    Breaking News 
  </button> 
 <puff> 
    <article v-if="showRecipe" class="card"> 
      <h3> 
        Apple Pie Recipe 
      </h3> 
      <p> 
        Ingredients: apple pie. Procedure: serve hot. 
      </p> 
    </article> 
 </puff> <puff> 
    <article v-if="showNews" class="card"> 
      <h3> 
        Breaking news 
      </h3> 
      <p> 
        Donald Duck is the new president of the USA. 
      </p> 
    </article> 
 </puff> 
</div>
```

现在，当按下按钮时，卡片将以“puff”效果出现和消失。

# 它是如何工作的...

我们代码中唯一棘手的部分是构建`<puff>`组件。一旦我们把它放在那里，无论我们放进去什么都会根据我们的过渡效果出现和消失。在我们的例子中，我们使用了一个已经制作好的过渡。在现实世界中，我们可能会制作一个非常复杂的动画，每次以相同的方式应用可能会很困难。将其打包在一个组件中更容易维护。

有两件事使`<puff>`组件作为可重用的过渡工作：

```js
props: { 
  'enter-active-class': 'magictime puffIn', 
  'leave-active-class': 'magictime puffOut' 
}
```

在这里，我们指定了组件在进入和离开时必须采用的类；这里没有什么特别的，我们已经在*与第三方 CSS 动画库集成，比如 animate.css*配方中做过了。

最后我们返回实际元素：

```js
return createElement('transition', data, context.children)
```

这一行创建了我们元素的根，是一个`<transition>`标签，只有一个子元素--`context.children`。这意味着子元素是未指定的；组件将把模板中传递的实际子元素作为子元素。在我们的例子中，我们传递了一些卡片，它们很快就显示出来了。

# 动态过渡

在 Vue 中，一个常数主题是反应性，当然，由于这个原因，过渡可以是动态的。不仅过渡本身，而且所有它们的属性都可以绑定到响应式变量上。这使我们对在任何给定时刻使用哪种过渡有很多控制。

# 准备工作

这个配方是建立在*元素之间过渡*配方之上的。如果你已经了解过渡，你不需要回去，但如果你觉得有所遗漏，最好先完成那个。

# 如何做...

我们将用一些吻把青蛙变成公主，但如果我们亲吻得太多，公主就会变成圣诞老人。当然，我们说的是表情符号。

我们的 HTML 设置非常简单：

```js
<div id="app"> 
  <button @click="kisses++">Kiss!</button> 
  <transition :name="kindOfTransformation" :mode="transformationMode"> 
    <p :key="transformation">{{emoji}}{{transformation}}</p> 
  </transition> 
</div>
```

只需注意这里大多数属性都绑定到变量上。以下是 JavaScript 的展开方式。

首先，我们将创建一个包含所有数据的简单 Vue 实例：

```js
new Vue({ 
el: '#app', 
  data: { 
    kisses: 0, 
    kindOfTransformation: 'fade', 
    transformationMode: 'in-out' 
  } 
})
```

我们所指的淡入淡出效果是以下 CSS：

```js
.fade-enter-active, .fade-leave-active { 
  transition: opacity .5s 
} 
.fade-enter, .fade-leave-active { 
  opacity: 0 
}
```

变量 transformation 和 emoji 由两个计算属性定义：

```js
computed: { 
  transformation () { 
    if (this.kisses < 3) { 
      return 'frog' 
    } 
    if (this.kisses >= 3 && this.kisses <= 5) { 
      return 'princess' 
    } 
    if (this.kisses > 5) { 
         return 'santa' 
    } 
  }, 
  emoji () { 
    switch (this.transformation) { 
      case 'frog': return '' 
      case 'princess': return '' 
      case 'santa': return '' 
    } 
  } 
}
```

当我们在青蛙和公主之间使用淡入淡出过渡时，我们希望在公主和青蛙之间使用其他过渡。我们将使用以下过渡类：

```js
.zoom-leave-active, .zoom-enter-active { 
  transition: transform .5s; 
} 

.zoom-leave-active, .zoom-enter { 
  transform: scale(0) 
}
```

现在，由于我们将过渡的名称绑定到一个变量，我们可以很容易地以编程方式进行切换。我们可以通过将以下突出显示的行添加到计算属性中来实现这一点：

```js
transformation () { 
  if (this.kisses < 3) { 
    return 'frog' 
  } 
  if (this.kisses >= 3 && this.kisses <= 5) { 
 this.transformationMode = 'out-in' 
    return 'princess' 
  } 
  if (this.kisses > 5) { 
 this.kindOfTransformation = 'zoom' 
    return 'santa' 
  } 
}
```

第一行添加的是为了避免在缩放转换开始时出现重叠（关于这一点，可以参考*让元素在过渡期离开之前离开*的内容）。

第二行添加的代码将动画切换为“缩放”。

为了使一切都以正确的方式出现，我们需要再添加一个 CSS 规则：

```js
p { 
  margin: 0; 
  position: absolute; 
  font-size: 3em; 
}
```

这样好多了。

现在运行应用程序，看看两种不同的转换是如何动态使用的：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/0019baba-8d2b-4051-9b82-f9a8dbae600b.png)

随着亲吻的次数增加，公主会缩小：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/bca613d9-9f69-4f92-b620-fbecfa645773.png)

有了这个，圣诞老人会放大：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/6827d454-44cf-4588-850d-b4dd0f82efdb.png)

# 它是如何工作的...

如果你了解 Vue 中响应式的工作原理，就没有太多要补充的了。我们将过渡的名称绑定到`kindOfTransformation`变量，并在代码中从淡入淡出切换到缩放。我们还演示了`<transition>`标签的其他属性也可以随时更改。
