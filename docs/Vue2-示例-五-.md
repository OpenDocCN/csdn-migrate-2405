# Vue2 示例（五）

> 原文：[`zh.annas-archive.org/md5/e39af983af3c7de00776f3c773ad8d42`](https://zh.annas-archive.org/md5/e39af983af3c7de00776f3c773ad8d42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：构建电子商务商店 - 添加结账功能

在过去的几章中，我们一直在创建一个电子商务商店。到目前为止，我们已经创建了一个产品页面，可以查看图片和产品变体，可能是尺寸或样式。我们还创建了一个带有过滤器和分页功能的类别页面 - 包括一个主页类别页面，其中包含特定的选定产品。

我们的用户可以浏览和筛选产品，并查看有关特定产品的更多信息。现在我们要做的是：

+   构建功能，允许用户将产品添加到购物篮中或从购物篮中删除产品

+   允许用户结账

+   添加一个订单确认页面

作为提醒 - 我们不会收集任何账单信息，但我们会创建一个订单确认页面。

# 创建购物篮数组占位符

为了帮助我们在整个应用程序中持久保存购物篮中的产品，我们将把用户选择的产品存储在 Vuex store 中。这将以对象数组的形式存在。每个对象将包含几个关键信息，这些信息将允许我们在不必每次查询 Vuex store 时都能显示购物篮中的产品。它还允许我们存储有关产品页面当前状态的详细信息 - 当选择变体时，记住图片更新。

我们要为每个添加到购物篮中的产品存储以下详细信息：

+   产品标题

+   产品句柄，以便我们可以链接回产品页面

+   选择的变体标题（在选择框中显示）

+   当前选择的图片，以便我们可以在结账时显示适当的图片

+   变体详情，包括价格、重量和其他细节

+   变体 SKU，这将帮助我们确定产品是否已经添加

+   数量，用户已添加到购物篮中的物品数量

由于我们将把所有这些信息存储在一个对象中，该对象包含在一个数组中，我们需要在商店中创建一个占位数组。在商店的`state`对象中添加一个名为`basket`的新键，并将其设置为空数组：

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

# 将产品信息添加到商店中

准备好接收数据的`basket`数组后，我们现在可以创建一个 mutation 来添加产品对象。打开`ProductPage.js`文件，并更新`addToBasket`方法，调用`$store`的 commit 函数，而不是我们之前放置的`alert`。

我们需要的所有添加到购物篮的产品信息都存储在`ProductPage`组件上，因此我们可以使用`this`关键字将组件实例传递给“commit（）”函数。当我们构建变异时，这将变得清晰起来。

将函数调用添加到`ProductPage`方法中：

```js
methods: {
  ...

 addToBasket() {
 this.$store.commit('addToBasket', this);
 }
}
```

# 创建存储变异以将产品添加到购物篮中

导航到 Vuex 存储并创建一个名为`addToBasket`的新变异。这将接受状态作为第一个参数，组件实例作为第二个参数。通过传递实例，我们可以访问组件上的变量、方法和计算值：

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

现在我们可以继续将产品添加到`basket`数组中。第一步是添加具有所述属性的产品对象。由于它是一个数组，我们可以使用“push（）”函数来添加对象。

接下来，使用`item`及其属性构建对象，将对象添加到数组中。通过访问`ProductPage`组件，我们可以使用`variantTitle`方法构建变体标题，该标题显示在选择框中。将数量默认设置为`1`：

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

现在将产品添加到`basket`数组中。然而，当您将两个相同的项目添加到购物篮时，会出现问题。它不会增加`quantity`，而是简单地添加第二个产品。

通过检查数组中是否已存在`sku`，可以解决此问题。如果存在，则可以增加该项的数量；如果不存在，则可以将新项添加到`basket`数组中。每个产品的每个变体的`sku`是唯一的。或者，我们可以使用条形码属性。

使用原生的 JavaScript`find`函数，我们可以识别出具有与传入的“sku”匹配的任何产品：

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
    variationTitle: item.variantTitle(item.variation),
    variation: item.variation,
    quantity: 1
  });
}
```

如果匹配，我们可以使用 JavaScript 中的`++`符号将该对象的数量增加一。如果不匹配，我们可以将新对象添加到`basket`数组中。使用`find`函数时，如果产品存在，我们可以返回该产品。如果不存在，我们可以添加一个新项目：

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

现在，当商品添加到购物篮时，购物篮会被填充，并且在已存在时会递增。

为了提高应用程序的可用性，当用户将商品添加到购物篮时，我们应该给予用户一些反馈。这可以通过简要更新“添加到购物篮”按钮并在网站标题中显示产品计数和指向购物篮的链接来实现。

# 更新添加商品时的“加入购物篮”按钮

作为对我们商店的可用性改进，当用户点击“Add to basket”按钮时，我们将更新它。这将变为“Added to your basket”，并在一定时间内应用一个类，例如两秒钟，然后返回到之前的状态。CSS 类将允许您以不同的方式样式化按钮，例如将背景更改为绿色或稍微变换。

这将通过在组件上使用一个数据属性来实现——将其设置为`true`和`false`，当商品添加时更改。CSS 类和文本将使用此属性来确定要显示什么，并且`setTimeout` JavaScript 函数将更改属性的状态。

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

更新按钮文本以适应这种变化。由于已经有一个三元`if`语句，我们将在其中嵌套另一个。如果需要，这可以抽象为一个方法。

在按钮的`Add to basket`条件中，用一个附加的三元运算符替换它，取决于`addedToBasket`变量是否为 true。我们还可以根据此属性添加一个条件类：

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
  }}
</button>
```

刷新应用程序并导航到一个产品，以确保显示正确的文本。将`addedToBasket`变量更新为`true`，以确保一切显示正常。然后将其设置回`false`。

接下来，在`addToBasket()`方法中，将属性设置为 true。当商品添加到购物篮时，这将更新文本：

```js
addToBasket() {
  this.$store.commit('addToBasket', this);

 this.addedToBasket = true;
}
```

当您点击按钮时，文本将会更新，但它永远不会重置。之后添加一个`setTimeout` JavaScript 函数，它会在一定时间后将其设置为`false`：

```js
addToBasket() {
  this.$store.commit('addToBasket', this);

  this.addedToBasket = true;
  setTimeout(() => this.addedToBasket = false, 2000);
}
```

`setTimeout`的时间单位是毫秒，所以`2000`等于两秒。随意调整和修改这个数字，以适应您的需求。

最后一个添加是，如果更新了变体或更改了产品，则将此值重置为`false`。将该语句添加到两个`watch`函数中：

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

# 在应用程序的页眉中显示产品计数。

在商店中，常见的做法是在网站的页眉中显示购物车链接，以及购物车中的商品数量。为了实现这一点，我们将使用一个 Vuex getter 来计算并返回购物篮中的商品数量。

打开`index.html`文件，将`<header>`元素添加到应用的 HTML 中，并插入一个占位符`span`，我们将在设置路由后将其转换为链接。在 span 中输出一个`cartQuantity`变量：

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

转到您的`Vue`实例并创建一个包含`cartQuantity`函数的`computed`对象：

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

如果我们的标题中的项目比购物车链接更多，建议将其抽象为单独的组件，以保持方法、布局和函数的封装。然而，由于在我们的示例应用程序中只会显示这一个链接，将函数添加到`Vue`实例中就足够了。

在 store 中创建一个名为`cartQuantity`的新 getter。作为占位符，返回`1`。计算数量需要使用`state`，因此现在将其传递给函数：

```js
getters: {
  ...

 cartQuantity: (state) => { 
 return 1;
 }
}
```

返回 getter 的结果到您的 Vue 实例。理想情况下，我们希望在括号中显示`basket`的数量，但只有在有物品时才显示括号。在计算函数中，检查此 getter 的结果，并在结果存在时以括号形式输出结果：

```js
cartQuantity() {
  const quantity = this.$store.getters.cartQuantity;
 return quantity ? `(${quantity})` : '';
}
```

更改 Vuex getter 中的结果应该显示括号中的数字或根本不显示。

# 计算购物篮数量

在显示逻辑就位后，我们现在可以继续计算篮子中有多少个物品。我们可以计算`basket`数组中的物品数量，但是这只会告诉我们现在有多少不同的产品，而不会告诉我们是否多次添加了同一种产品。

相反，我们需要遍历篮子中的每个产品并将数量相加。创建一个名为`quantity`的变量并将其设置为`0`。遍历篮子中的物品并将`item.quantity`变量添加到`quantity`变量中。最后，返回我们的变量与正确的总和：

```js
cartQuantity: (state) => {
 let quantity = 0;
 for(let item of state.basket) {
 quantity += item.quantity;
 }
 return quantity;
}
```

转到应用程序并添加一些物品到您的篮子，以验证篮子计数是否被正确计算。

# 完成 Shop Vue-router 的 URL

现在我们可以最终确定我们商店的 URL，包括创建重定向和结账链接。回顾第八章，*介绍 Vue-Router 和加载基于 URL 的组件*，我们可以看到我们缺少哪些。它们是：

+   `/category` - 重定向到`/`

+   `/product` - 重定向到`/`

+   `/basket` - 加载`OrderBasket`组件

+   `/checkout`- 加载`OrderCheckout`组件

+   `/complete`- 加载`OrderConfirmation`组件

在路由数组的适当位置创建重定向。在路由数组的底部，为`Order`组件创建三个新的路由：

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

现在，我们可以使用`router-link`来更新应用程序标题中的占位符`<span>`：

```js
<header>
  <router-link :to="{name: 'Basket'}">Cart {{ cartQuantity }}</router-link>
</header>
```

# 构建订单流程和 ListProducts 组件

对于结账的三个步骤，我们将在所有三个步骤中使用相同的组件：`ListProducts`组件。在`OrderCheckout`和`OrderConfirmation`组件中，它将处于固定的、不可编辑的状态，而在`OrderBasket`组件中，用户需要能够更新数量和删除物品。

由于我们将在结账时工作，我们需要在`basket`数组中存在产品。为了避免每次刷新应用程序时都要查找产品并将其添加到购物篮中，我们可以通过在商店中硬编码一个数组来确保`basket`数组中有一些产品。

为了实现这一点，浏览一些产品并将它们添加到购物篮中。确保有一些产品和数量以供测试。接下来，在浏览器中打开 JavaScript 控制台，并输入以下命令：

```js
console.log(JSON.stringify(store.state.basket));
```

这将输出一个包含产品数组的字符串。将其复制并粘贴到您的商店中，替换`basket`数组：

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

现在我们可以继续构建我们的结账流程了。购物篮中的产品显示比结账和订单确认屏幕更复杂，所以我们将反向工作。从订单确认页面开始，然后转到结账页面，在前进到购物篮之前，增加更多的复杂性，添加退出产品的功能。

# 订单确认屏幕

订单确认屏幕是在订单完成后显示的屏幕。它确认购买的物品，并可能包括预计的交付日期。

在`OrderConfirmation.js`文件中创建一个模板，其中包含一个`<h1>`和与订单完成相关的一些内容：

```js
const OrderConfirmation = {
  name: 'OrderConfirmation',

  template: `<div>
    <h1>Order Complete!</h1>
    <p>Thanks for shopping with us - you can expect your products within 2 - 3 working days</p>
  </div>`
};
```

在浏览器中打开应用程序，将产品添加到购物篮中并完成订单以确认它是否正常工作。下一步是包含`ListProducts`组件。首先，确保`ListProducts`组件正确初始化并具有初始模板：

```js
const ListPurchases = {
  name: 'ListPurchases',

  template: `<table></table>`
};
```

在`OrderConfirmation`组件中添加`components`对象，并包含`ListProducts`组件。接下来，在模板中包含它：

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

再次打开`ListPurchases`组件以开始显示产品。该组件的默认状态将是列出购物篮中的产品，以及所选的变体。每个产品的价格将被显示，如果数量大于一，则还会显示价格。最后，将显示一个总计。

第一步是将购物篮列表放入我们的组件中。创建一个带有`products`函数的`computed`对象。这应该返回购物篮中的产品：

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

现在我们可以在显示所需信息的表格中循环遍历购物篮中的产品。这包括缩略图、产品和变体标题、价格、数量和项目的总价格。还要在表格中添加一个标题行，以便用户知道该列是什么：

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

注意每行的价格只是单位价格乘以数量。现在我们有了用户购买的标准产品清单。

# 使用 Vue 过滤器格式化价格

价格当前是一个整数，因为它在数据中。在产品页面上，我们只是在价格前面添加了一个`$`符号来表示价格，然而，现在正是利用 Vue 过滤器的绝佳机会。过滤器允许您在模板中操作数据而不使用方法。过滤器可以链接在一起，用于执行通常的单一修改，例如将字符串转换为小写或格式化数字为货币。

过滤器与管道（`|`）操作符一起使用。例如，如果我们有一个将文本转换为小写的过滤器，可以像下面这样使用：

```js
{{ product.title | lowercase }}
```

过滤器在组件的`filters`对象中声明，并接受一个参数作为输出的前导。

在`ListPurchases`组件中创建一个`filters`对象，并在其中创建一个名为`currency()`的函数。该函数接受一个名为`val`的参数，并应返回该变量：

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

在浏览器中你不会注意到任何变化，因为我们还没有操作该值。更新函数以确保数字保留两位小数并在前面加上`$`：

```js
filters: {
  currency(val) {
    return ' + val.toFixed(2);
  }
},
```

我们的价格现在格式化得很好，并且显示正确。

# 计算总价格

我们购买清单的下一个添加是购物篮的总价值。这需要以与我们之前计算购物篮数量类似的方式进行计算。

创建一个名为`totalPrice`的新的`computed`函数。该函数应该循环遍历产品并累加价格，考虑到任何多个数量：

```js
totalPrice() {
  let total = 0;

  for(let p of this.products) {
    total += (p.variation.price * p.quantity);
  }

  return total;
}
```

现在我们可以更新模板，包括总价格，确保我们通过`currency`过滤器传递它：

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

我们的`OrderCheckout`页面的结构与`OrderConfirmation`页面类似-然而，在一个真实的商店中，这将是付款之前的页面。在导航到付款页面之前，该页面允许用户填写他们的账单和送货地址。复制`OrderConfirmation`页面并更新标题和信息文本：

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

在`<list-purchases />`组件下方创建一个表单，包含多个字段，以便我们收集账单和送货人姓名和地址。在这个例子中，只需收集姓名、地址的第一行和邮政编码：

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

现在我们需要创建一个数据对象，并将每个字段绑定到一个键上。为了帮助分组每个集合，创建一个`delivery`和`billing`的对象，并在内部创建正确的字段名称：

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

为每个输入框添加`v-model`，将其与相应的数据键进行关联：

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

下一步是创建一个`submit`方法，并整理数据以便能够传递给下一个页面。创建一个名为`submitForm()`的新方法。由于本例中不处理付款，所以我们可以在该方法中跳转到确认页面：

```js
methods: {
  submitForm() {
    // this.billing = billing details
    // this.delivery = delivery details

    this.$router.push({name: 'Confirmation'});
  }
}
```

现在我们可以将`submit`事件绑定到表单上，并添加一个提交按钮。与`v-bind:click`属性（或`@click`）类似，Vue 允许你使用`@submit=""`属性将`submit`事件绑定到一个方法上。

在你的表单中，为`<form>`元素添加声明，并创建一个提交按钮：

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

一项几家商店都具备的功能是将送货地址标记为与账单地址相同。我们可以采用几种方法来实现这一功能，你可以根据自己的选择来进行操作。以下是一些可行的选项：

+   添加一个“复制详细信息”按钮-这将从账单复制详细信息到送货地址，但不保持它们同步

+   添加一个复选框，保持两者同步-勾选该框将禁用送货地址字段，但使用账单详细信息填充它们

在这个例子中，我们将编写第二个选项的代码。

在两个字段集之间创建一个复选框，通过`v-model`属性绑定到数据对象中的一个属性，属性名为`sameAddress`：

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

下一步是如果复选框被勾选，则禁用交付字段。这可以通过根据复选框的结果激活`disabled`HTML 属性来实现。类似于我们在产品页面上禁用“添加到购物车”按钮的方式，将交付字段上的禁用属性绑定到`sameAddress`变量上：

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

现在勾选复选框将禁用字段 - 用户无法输入任何数据。下一步是在两个部分之间复制数据。由于我们的数据对象具有相同的结构，我们可以创建一个`watch`函数，当复选框被勾选时，将`delivery`对象设置为与`billing`对象相同。

为`sameAddress`变量创建一个新的`watch`对象和函数。如果它为`true`，则将交付对象设置为与账单对象相同：

```js
watch: {
  sameAddress() {
    if(this.sameAddress) {
      this.delivery = this.billing;
    }
  }
}
```

添加了`watch`函数后，我们可以输入数据到账单地址，勾选复选框，然后交付地址会自动填充。最好的是它们现在保持同步，所以如果你更新了账单地址，交付地址会实时更新。问题出现在当你取消勾选复选框并编辑账单地址时，交付地址仍然会更新。这是因为我们将这两个对象绑定在一起。

添加一个`else`语句，在取消勾选复选框时复制账单地址：

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

现在我们有一个功能齐全的订单确认页面，可以收集账单和交付详细信息。

# 创建可编辑的购物篮

现在我们需要创建我们的购物篮。它需要以类似的方式显示产品，如结账和确认页面，但它需要给用户编辑购物篮内容的能力 - 删除项目或更新数量。

作为起点，打开`OrderBasket.js`并包含`list-purchases`组件，就像在确认页面上一样：

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

接下来我们需要编辑`list-purchases`组件。为了确保我们可以区分视图，我们将添加一个`editable`属性。默认情况下设置为`false`，在购物篮中设置为`true`。在购物篮中的组件中添加`prop`：

```js
template: `<div>
  <h1>Basket</h1>
  <list-purchases :editable="true" />
</div>`,
```

现在我们需要告诉`ListPurchases`组件接受这个参数，以便我们可以在组件内部处理它：

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

在`ListPurchases`组件中的数量旁边创建一个新的表格单元格，并仅在购买可见时使其可见。在此状态下，也隐藏静态数量。在新单元格中，添加一个值设置为数量的输入框。我们还将为框绑定一个`blur`事件。`blur`事件是一个原生 JavaScript 事件，当输入框失去焦点时触发。在失去焦点时，触发`updateQuantity`方法。此方法应接受两个参数：事件（其中包含新数量）和该特定产品的 SKU：

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

在组件上创建新方法。此方法应该循环产品，找到具有匹配 SKU 的产品并将数量更新为整数。我们还需要使用结果更新存储，以便在页面顶部更新数量。我们将创建一个通用的突变，接受带有新值的完整`basket`数组，以允许在产品删除时使用相同的突变。

创建更新数量并提交名为`updatePurchases`的突变。

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

在商店中，创建将`state.basket`设置为有效载荷的突变：

```js
updatePurchases(state, payload) {
  state.basket = payload;
}
```

更新数量现在应该更新项目的总价格和页面顶部的购物篮计数。

# 从购物车中删除商品

下一步是让用户能够从购物车中删除商品。在`ListPurchases`组件中创建一个带有点击绑定的按钮。此按钮可以放在任何位置-我们的示例将其显示为行末的额外单元格。将点击操作绑定到名为`removeItem`的方法。这只需要接受一个 SKU 的参数。在`ListPurchases`组件中添加以下内容：

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

创建`removeItem`方法。此方法应该过滤`basket`数组，只返回与传入的 SKU 不匹配的对象。过滤结果后，将结果传递给我们在`updateQuantity()`方法中使用的相同突变：

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

我们可以进行的最后一个改进是，如果数量设置为 0，则触发`removeItem`方法。在`updateQuantity`方法中，循环产品之前检查值。如果它是`0`或不存在，则运行`removeItem`方法-通过传递 SKU：

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

最后一步是在`OrderBasket`组件中添加一个链接到`OrderCheckout`页面。这可以通过链接到`Checkout`路由来完成。有了这个，你的结账就完成了，你的商店也完成了！在购物篮中添加以下链接：

```js
template: `<div>
  <h1>Basket</h1>
  <list-purchases :editable="true" />
  <router-link :to="{name: 'Checkout'}">Proceed to Checkout</router-link>
</div>`,
```

# 总结

干得好！你已经使用`Vue.js`创建了一个完整的商店单页面应用程序。你学会了如何列出产品及其变体，以及如何将特定的变体添加到购物篮中。你学会了如何创建商店过滤器和类别链接，以及创建可编辑的购物篮。

像其他事情一样，总是有改进的空间。为什么不试试这些想法呢？

+   使用`localStorage`持久化购物篮-这样添加到购物篮中的产品在访问和用户按下刷新按钮之间会保留下来

+   根据购物篮中产品的重量属性计算运费-使用 switch 语句创建带有不同范围的运费

+   允许将没有变体的产品从类别列表页面添加到购物篮中

+   在类别页面上对具有缺货项的产品进行筛选时指示

+   有没有自己的想法！


# 第十二章：使用 Vue Dev Tools 和测试您的 SPA

在过去的 11 章中，我们使用`Vue.js`开发了几个单页应用程序（SPA）。尽管开发是创建 SPA 的重要部分，但测试也是创建任何 JavaScript Web 应用程序的重要组成部分。

Vue 开发者工具在 Chrome 和 Firefox 中可用，可以提供对在特定视图中使用的组件或 Vuex 存储的当前状态的深入了解，以及从 JavaScript 中发出的任何事件。这些工具允许您在开发过程中检查和验证应用程序中的数据，以确保一切都正常。

SPA 测试的另一方面是自动化测试。您编写的条件、规则和路由用于自动化执行应用程序中的任务，允许您指定输出应该是什么，并且测试运行条件以验证结果是否匹配。

在本章中，我们将：

+   使用我们开发的应用程序介绍 Vue 开发者工具的用法

+   概述测试工具和应用程序

# 使用 Vue.js 开发者工具

Vue 开发者工具适用于 Chrome 和 Firefox，并可从 GitHub（[`github.com/vuejs/vue-devtools`](https://github.com/vuejs/vue-devtools)）下载。安装后，它们成为浏览器开发者工具的扩展。例如，在 Chrome 中，它们出现在审核选项卡之后。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00022.jpeg)

只有在使用 Vue 开发模式时，Vue 开发者工具才能正常工作。默认情况下，未经压缩的 Vue 版本启用了开发模式。但是，如果您使用的是代码的生产版本，则可以通过在代码中将`devtools`变量设置为`true`来启用开发工具：

```js
Vue.config.devtools = true
```

在本书中，我们一直使用 Vue 的开发版本，因此开发工具应该适用于我们开发的所有三个 SPA。打开 Dropbox 示例并打开 Vue 开发者工具。

# 检查 Vue 组件的数据和计算值

Vue 开发者工具提供了页面上正在使用的组件的很好概述。您还可以深入了解组件并预览在该特定实例上使用的数据。这非常适合在任何给定时间检查页面上每个组件的属性。

例如，如果我们检查 Dropbox 应用程序并导航到组件选项卡，我们可以看到<Root> Vue 实例和<DropboxViewer>组件。点击这个将显示组件的所有数据属性 - 以及任何计算属性。这样我们就可以验证结构是否正确构建，以及计算路径属性：

！[](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00023.jpeg)

深入研究每个组件，我们可以访问单个数据对象和计算属性。

使用 Vue 开发者工具来检查应用程序是一种更高效的验证数据的方式，因为它避免了使用多个`console.log()`语句。

# 查看 Vuex 的 mutations 和时间旅行

导航到下一个选项卡 Vuex，可以实时观察 store mutations 的发生。每次发生 mutation 时，左侧面板中都会创建一行新的。这个元素允许我们查看发送的数据以及数据提交之前和之后的 Vuex store 的样子。

它还提供了几个选项来还原、提交和时间旅行到任何点。加载 Dropbox 应用程序后，左侧面板中立即出现了几个结构 mutations，列出了 mutation 的名称和发生的时间。这是代码预缓存文件夹的操作。点击每个选项将显示 Vuex store 的状态 - 以及包含的 payload 的 mutation。状态显示是在 payload 发送和 mutation 提交之后。要预览该 mutation 之前的状态，请选择前面的选项：

！[](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00024.jpeg)

在每个条目旁边，您会注意到三个符号，允许您执行多个操作并直接在浏览器中改变 store：

+   **提交此 mutation**：这允许您提交到该点的所有数据。这将从开发工具中*删除*所有的 mutations，并将基本状态更新到此点。如果有多个 mutations 发生，您希望跟踪它们，这将非常方便。

+   **还原此变化**：这将撤消该变化和此点之后的所有变化。这使您可以一遍又一遍地执行相同的操作，而无需刷新或丢失当前位置。例如，在我们的购物应用程序中将产品添加到购物篮时，会发生变化。使用此功能，您可以从购物篮中删除产品并撤消任何后续变化，而无需离开产品页面。

+   **时间旅行到此状态**：这允许您预览应用程序和该特定变化状态，而不会还原所选点之后发生的任何变化。

变化选项卡还允许您在左侧面板顶部提交或还原所有变化。在右侧面板中，您还可以导入和导出存储状态的 JSON 编码版本。当您想要重新测试多种情况和实例而不必重复多个步骤时，这非常方便。

# 预览事件数据

Vue 开发者工具的事件选项卡与 Vuex 选项卡类似，允许您检查应用程序中发出的任何事件。我们的 Dropbox 应用程序不使用事件，因此打开我们在本书的第二章和第三章中创建的 people-filtering 应用程序，*显示、循环、搜索和过滤数据*以及*优化我们的应用程序并使用组件显示数据*。

更改此应用程序中的过滤器会在每次更新过滤器类型时触发一个事件，同时附带过滤器查询：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00025.jpeg)

左侧面板再次列出事件的名称和发生时间。右侧面板包含有关事件的信息，包括其组件来源和有效负载。这些数据可以确保事件数据与您预期的一样，如果不是，可以帮助您找到触发事件的位置。

Vue 开发工具非常宝贵，特别是在您的 JavaScript 应用程序变得越来越大和复杂时。打开我们开发的购物 SPA，并检查各个组件和 Vuex 数据，以了解这个工具如何帮助您创建只提交所需变化并发出所需事件的应用程序。

# 测试您的 SPA

大多数 Vue 测试套件都围绕着具备命令行知识并使用 CLI（命令行界面）创建 Vue 应用程序。除了使用前端兼容的 JavaScript 创建应用程序外，Vue 还有一个 CLI，允许您使用基于组件的文件创建应用程序。这些文件的扩展名为`.vue`，包含模板 HTML 以及组件所需的 JavaScript。它们还允许您创建作用域 CSS-仅适用于该组件的样式。如果选择使用 CLI 创建应用程序，您在本书中学到的所有理论知识和大部分实践知识都可以轻松移植过来。

# 命令行单元测试

除了组件文件之外，Vue CLI 还允许您更轻松地与命令行单元测试集成，例如 Jest、Mocha、Chai 和 TestCafe（[`testcafe.devexpress.com/`](https://testcafe.devexpress.com/)）。例如，TestCafe 允许您指定多个不同的测试，包括检查内容是否存在，点击按钮以测试功能等。一个 TestCafe 测试的示例是检查我们第一个应用程序中的过滤组件是否包含单词*Field*：

```js
test('The filtering contains the word "filter"', async testController => {
  const filterSelector = await new Selector('body > #app > form > label:nth-child(1)');

  await testController.expect(paragraphSelector.innerText).eql('Filter');
});
```

这个测试将返回`true`或`false`。单元测试通常与组件本身一起编写，允许组件在隔离环境中被重用和测试。这样可以确保外部因素对测试结果没有影响。

大多数命令行 JavaScript 测试库都可以与 Vue.js 集成；在 awesome Vue GitHub 存储库中有一个很棒的列表可用（[`github.com/vuejs/awesome-vue#test`](https://github.com/vuejs/awesome-vue#test)）。

# 浏览器自动化

使用命令行单元测试的替代方法是使用测试套件自动化浏览器。这种测试仍然通过命令行触发，但与其直接集成 Vue 应用程序不同，它会在浏览器中打开页面并像用户一样与其交互。一个常用的工具是`Nightwatch.js`（[`nightwatchjs.org/`](http://nightwatchjs.org/)）。

您可以使用此套件来开设您的商店，并与过滤组件或产品列表进行交互，以及对结果进行排序和比较。这些测试用例使用非正式的英语编写，并不限于与要测试的网站在同一域名或文件网络上。该库也是语言无关的，适用于任何网站，无论其使用何种构建方式。

Nightwatch.js 在其网站上给出的示例是打开 Google 并确保`rembrandt van rijn`的 Google 搜索结果的第一个结果是维基百科的条目。

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

与 Nightwatch 相比，Selenium（[`www.seleniumhq.org/`](http://www.seleniumhq.org/)）是一种替代方案。Selenium 具有一个 Firefox 扩展，可以让您可视化地创建测试用例和命令。

测试，特别是对于大型应用程序来说，是至关重要的，尤其是在将应用程序部署到开发环境时。无论您选择单元测试还是浏览器自动化，都有大量的文章和书籍可供参考。

# 总结

在本书中，我们介绍了几种技术，并学习了如何使用 Vue 和官方 Vue 插件。我们构建了三个单页面应用程序，涵盖了不同的方法和方式。

在本书的第一部分中，我们介绍了如何初始化 Vue 实例。我们探讨了如何循环遍历数据以及如何创建用户界面来过滤显示的数据。我们还介绍了如何在每一行上有条件地渲染 CSS 类。

然后，我们开始将 Vuex 集成到我们的应用程序中，并与 API 进行通信，以 Dropbox 为例。我们研究了如何访问数据并将其存储在本地。这有助于提高应用程序的性能和速度，改善用户体验。

最后，我们创建了一个模拟商店。使用来自 Shopify CSV 文件的真实数据，我们创建了一个允许单独查看产品的应用程序。我们还创建了一个可以进行过滤和排序的类别列表页面，使用户能够找到他们想要的特定产品。为了完善体验，我们构建了一个可编辑的购物篮、结账和订单确认界面。

在本章中，我们介绍了使用 Vue 开发工具，以及如何构建测试用例。这完成了使用`Vue.js`构建单页面应用程序的过程。
