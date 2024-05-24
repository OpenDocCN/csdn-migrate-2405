# jQuery 游戏开发基础（二）

> 原文：[`zh.annas-archive.org/md5/7D66632184130FBF91F62E87E7F01A36`](https://zh.annas-archive.org/md5/7D66632184130FBF91F62E87E7F01A36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：视角透视

现在我们将看到如何渲染另一种非常流行的效果：俯视透视（也称为俯瞰透视）。可以使用这种技术创建各种不同的游戏：

+   类似 *大逃杀* 的动作游戏

+   类似 *外星宝贝* 的射击游戏

+   类似于 *塞尔达传说* 或 *超时空战记* 的 RPG

+   类似于 *模拟城市* 的模拟

+   类似于 *文明* 或 *魔兽争霸* 的战争游戏

这些游戏使用的是所谓的正投影。可以使用简单的瓦片地图轻松渲染，就像我们在上一章中实现的那样。在本章中，我们将制作一个看起来像 *塞尔达传说：超级任天堂时代* 在超级任天堂上的角色扮演游戏。

我们将使用来自 BrowserQuest（[`browserquest.mozilla.org`](http://browserquest.mozilla.org)）的图形资产，这是 Mozilla 开发的非常酷的开源游戏，用于展示现代浏览器的能力。您可以在下面的截图中看到：

![视角透视](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_15.jpg)

在本章中，我们将涵盖以下主题：

+   瓦片地图优化

+   精灵层遮挡

+   高级碰撞检测

在本章末尾，我们将快速讨论另一种可以用于相同类型游戏的俯视视图变体：2.5D 或等距投影。

# 优化俯视游戏的瓦片地图

我们在上一章实现的瓦片地图非常适合侧向滚动游戏，因为它们通常使用稀疏矩阵来定义它们的级别。这意味着如果你的级别长 100 个瓦片，高 7 个瓦片，那么它将包含远少于 700 个瓦片。这使我们能够在游戏开始时创建所有这些瓦片。

对于典型的俯视游戏，我们发现自己处于非常不同的情况。的确，为了渲染地图，定义了使用的瓦片地图的所有可能瓦片。这意味着对于相同尺寸的级别，我们将至少有 700 个瓦片。如果使用多个图层，情况会变得更糟。为了减少这个数字以提高性能，我们将只生成在启动时可见的瓦片。然后当视图移动时，我们将跟踪哪些瓦片变得不可见并删除它们，哪些瓦片变得可见并生成它们。

这里存在一个权衡；添加和删除瓦片会花费一些时间，而且很有可能会使游戏变慢。另一方面，在场景中有大量的瓦片并移动它们会使渲染变慢。

理想情况下，在两种技术之间做出选择是测试两种技术，找出哪种在目标平台上产生更好的结果。如果你真的需要，甚至可以使用混合方案，其中你按块生成瓦片地图。这将允许你调整何时容忍由于创建和删除瓦片而导致的减速。

在这里，我们将修改框架以仅显示可见的瓦片，并且已经证明对于这种玩家以合理速度移动且世界通常相当大的游戏来说，这已经足够快了。

## 查找可见瓦片

好消息是我们已经有了大部分需要找到可见瓦片的代码。实际上，我们有一个函数，它返回与一个框碰撞的瓦片。要找到可见瓦片，我们只需要将此框定义为游戏屏幕。

```js
// find the visible part
var offset = gf.offset(parent);
var visible = gf.tilemapBox(options, {
       x:      -options.x - offset.x, 
       y:      -options.x - offset.y, 
       width:  gf.baseDiv.width(),
       height: gf.baseDiv.height()
});
```

在这里，您可以看到我们使用一个函数来找到瓦片地图的偏移量。这是必需的，因为它可能嵌套在一个或多个已移动的组中。

要找到偏移量，我们只需查看当前元素及其所有父元素。如果父元素不是精灵、组或瓦片地图，则会停止。如果父元素是基本的 div，即用于容纳整个游戏的 div，也会停止。

```js
gf.offset = function(div){
   var options = div.data("gf");
   var x = options.x;
   var y = options.y;

   var parent = $(div.parent());
   options = parent.data("gf");
   while (!parent.is(gf.baseDiv) && options !== undefined){
      x += options.x;
      y += options.y;
      parent = $(parent.parent());
      options = parent.data("gf");
   }
   return {x: x, y: y};
}
```

要查找父元素是否为组、精灵或瓦片地图，我们检查与键“data”关联的对象是否存在。

除了找到可见框的部分之外，`addTilemap`函数本身并没有太多变化。以下是带有更改部分的其简短版本：

```js
gf.addTilemap = function(parent, divId, options){
    var options = $.extend({
        x: 0,
        ...
    }, options);

    // find the visible part
 var offset = gf.offset(parent);
 var visible = gf.tilemapBox(options, {
 x:      -options.x - offset.x,
 y:      -options.x - offset.y,
 width:  gf.baseDiv.width(),
 height: gf.baseDiv.height()
 });
 options.visible = visible;

    //create line and row fragment:
    var tilemap = gf.tilemapFragment.clone().attr("id",divId).data("gf",options);
    for (var i=visible.y1; i < visible.y2; i++){
        for(var j=visible.x1; j < visible.x2; j++) {
            var animationIndex = options.map[i][j];

            ...
        }
    }
    parent.append(tilemap);
    return tilemap;
}
```

## 移动瓦片地图

现在我们必须跟踪瓦片地图的移动以更新哪些是可见的。由于我们有两个函数来移动任何元素，所以我们只需修改它们。

但是，我们不能只在瓦片地图移动时更新它们；当其任何父元素移动时，我们还必须更新它们。jQuery 提供了一种非常简单的方法来查找元素是否具有瓦片地图作为其子元素或孙子元素：`.find()`。此函数搜索与提供的选择器匹配的任何子元素。

由于我们将类`gf_tilemap`添加到每个瓦片地图中，因此检测它们非常容易。以下代码是带有更改的新`gf.x`函数。`gf.y`函数完全相同。

```js
gf.x = function(div,position) {
    if(position !== undefined) {
        div.css("left", position);
        div.data("gf").x = position;

        // if the div is a tile map we need to update the visible part
        if(div.find(".gf_tilemap").size()>0){
 div.find(".gf_tilemap").each(function(){gf.updateVisibility($(this))});
 }
 if(div.hasClass("gf_tilemap")){
 gf.updateVisibility($(div));
 }
    } else {
        return div.data("gf").x; 
    }
}
```

如果子元素中的一个，或者元素本身，是瓦片地图，则需要更新它。我们使用`gf.updateVisibility()`函数来执行此操作。此函数仅在瓦片地图中找到新的可见框并将其与旧的框进行比较。这意味着我们必须将这种可见性存储在精灵的数据中。

下面的代码是此函数的完整实现：

```js
gf.updateVisibility = function(div){
   var options = div.data("gf");
   var oldVisibility = options.visible;

    var parent = div.parent();

    var offset = gf.offset(div);
   var newVisibility = gf.tilemapBox(options, {
       x:      -offset.x,
       y:      -offset.y,
       width:  gf.baseDiv.width(),
       height: gf.baseDiv.height()
    });

    if( oldVisibility.x1 !== newVisibility.x1 ||
       oldVisibility.x2 !== newVisibility.x2 ||
       oldVisibility.y1 !== newVisibility.y1 ||
       oldVisibility.y2 !== newVisibility.y2){

       div.detach();

       // remove old tiles 
       for(var i = oldVisibility.y1; i < newVisibility.y1; i++){
          for (var j = oldVisibility.x1; j < oldVisibility.x2; j++){
             div.find(".gf_line_"+i+".gf_column_"+j).remove();
          }
       }
       for(var i = newVisibility.y2; i < oldVisibility.y2; i++){
          for (var j = oldVisibility.x1; j < oldVisibility.x2; j++){
             div.find(".gf_line_"+i+".gf_column_"+j).remove();
          }
       }
       for(var j = oldVisibility.x1; j < newVisibility.x1; j++){
          for(var i = oldVisibility.y1; i < oldVisibility.y2; i++){
             div.find(".gf_line_"+i+".gf_column_"+j).remove();
          }
       }
       for(var j = newVisibility.x2; j < oldVisibility.x2; j++){
          for(var i = oldVisibility.y1; i < oldVisibility.y2; i++){
             div.find(".gf_line_"+i+".gf_column_"+j).remove();
          }
       }
       // add new tiles

       for(var i = oldVisibility.y2; i < newVisibility.y2; i++){
          for (var j = oldVisibility.x1; j < oldVisibility.x2; j++){
             createTile(div,i,j,options);
          }
       }
       for(var i = newVisibility.y1; i < oldVisibility.y1; i++){
          for (var j = oldVisibility.x1; j < oldVisibility.x2; j++){
             createTile(div,i,j,options);
          }
       }
       for(var j = oldVisibility.x2; j < newVisibility.x2; j++){
          for(var i = oldVisibility.y1; i < oldVisibility.y2; i++){
             createTile(div,i,j,options);
          }
       }
       for(var j = newVisibility.x1; j < oldVisibility.x1; j++){
          for(var i = oldVisibility.y1; i < oldVisibility.y2; i++){
             createTile(div,i,j,options);
          }
       }
       div.appendTo(parent);

    }
    // update visibility
    options.visible = newVisibility;
}
```

前四个循环用于删除不再可见的现有瓦片。我们不再测试要删除的瓦片是否在顶部或底部，而是写两个循环。代码中的第一个循环写得好像要删除的瓦片在顶部。如果要删除的瓦片实际上在底部，如下图所示，该循环将不会执行，因为`oldVisibility.y1 > newVisibility.y1`。

![移动瓦片地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_01.jpg)

如果砖块要从顶部、左侧或右侧删除，我们会使用相同的机制添加新的砖块。然而，有一件事情需要我们小心; 当我们先水平添加砖块时，当我们垂直添加它们时，我们必须确保不要再次创建我们已经创建的砖块。下图显示了重叠的砖块:

![移动瓦片地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_02.jpg)

有更加优雅的方法来实现这一点，但在这里，我们只是在创建砖块之前检查是否存在这样一个砖块。这是在`gf.createTile`函数中完成的。

```js
var createTile = function(div, i,j,options){
   var animationIndex = options.map[i][j];
   if(animationIndex > 0 && div.find(".gf_line_"+i+".gf_column_"+j).size() === 0){
       var tileOptions = {
            x: options.x + j*options.tileWidth,
            y: options.y + i*options.tileHeight,
            width: options.tileWidth,
            height: options.tileHeight
        }
        var tile = gf.spriteFragment.clone().css({
            left:   tileOptions.x,
            top:    tileOptions.y,
            width:  tileOptions.width,
            height: tileOptions.height}
        ).addClass("gf_line_"+i).addClass("gf_column_"+j).data("gf", tileOptions);

        gf.setAnimation(tile, options.animations[animationIndex-1]);

        div.append(tile);
    }
}
```

有了这两个改变，瓦片地图现在是动态生成的。

# 排序遮挡

在使用俯视视图时，我们将遇到两种可能性中的一种: 要么“摄像机”直接望向地面，要么呈轻微的角度。下图说明了这两种情况:

![排序遮挡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_03.jpg)

在第一种情况下，唯一一个元素被另一个元素隐藏的情况是它直接在上面。要产生这种效果非常容易;我们只需为每个高度使用一个组，并将精灵和瓦片地图放入正确的组中。

例如，让我们考虑一个包含树和桥的关卡，玩家可以在桥下行走，就像下图中的情况:

![排序遮挡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_04.jpg)

我们可以像这样组织我们的游戏屏幕:

![排序遮挡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_05.jpg)

一旦完成这个步骤，就没什么好担心的了。如果 NPC（非玩家角色）或玩家在某个时刻上下移动，我们只需将他们从一个组中移除并添加到另一个组中。

然而，大多数现代游戏使用第二种视角，并且这也是我们小游戏将使用的视角。在这种透视中，不仅是上面的元素会覆盖其他元素，前面的元素也可能会隐藏它们。下图说明了这一点：

![排序遮挡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_06.jpg)

为了想出一个严格通用的解决方案对于大多数游戏来说可能有点过度，而且可能会产生一些性能问题。相反，我们将使用以下技巧来产生令人信服的效果。

## 精灵屏蔽

如果我们做出以下假设，精灵的情况就会变得简单:

+   地面是完全平坦的。可能有许多不同高度的平坦“楼层”，但它们每一个都是平坦的。

+   两个平坦楼层之间的高度差大于最大 NPC 或玩家的尺寸。

通过这些限制，我们可以用以下两个规则管理精灵的遮挡:

+   如果一个精灵在比另一个更高的楼层上，则前者将始终隐藏后者。

+   如果两个精灵在同一楼层上，则 y 坐标较大的那个将始终隐藏另一个

实现这个最简单的方式是使用`z-index` CSS 属性。实现看起来会像这样:

```js
gf.y(this.div, y);
this.div.css("z-index", y + spriteHeight);
```

这里我们需要将精灵的高度加到 y 坐标上，因为我们需要考虑的是遮挡的底部而不是顶部。

如果精灵所在的楼层高一层，我们将确保其 z 索引大于上方所有楼层中的所有精灵。假设我们给每个层级分配一个索引，0 表示最低层，1 表示上方的一层，依此类推；在这种情况下，从 y 坐标生成 z 索引的公式将是：

```js
z-index = y-coordinate + spriteHeight + floorIndex * floorHeight
```

在我们的游戏中，所有的精灵都将处于同一水平线上，因此我们不需要使用这个函数，而且我们可以坚持使用之前的代码。

## 关卡与精灵的遮挡

如果我们仍然保持之前的假设，那么我们不需要做太多工作来从背景中生成精灵的遮挡。我们的关卡是使用瓦片地图定义的。在设计关卡时，我们将我们的瓦片分成两个瓦片地图：一个是地板，另一个是地板上方的所有内容。

举例来说，让我们考虑一个场景，有一棵树和一座房子：

![关卡与精灵的遮挡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_07.jpg)

我们将地面、房子底部和树干存储在一个瓦片地图中，而将房顶和树叶存储在另一个瓦片地图中。

# 碰撞检测

对于此游戏，碰撞检测与之前的游戏略有不同。由于我们使用的是碰撞而不是与精灵边界框的每个像素的碰撞，我们可能会出现仅有精灵的非透明像素发生碰撞的情况，如下图所示：

![碰撞检测](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_08.jpg)

然而，有一个非常简单的解决方案来解决这个问题，而不需要使用每个像素或多边形碰撞检测；我们将使用第二个透明精灵来创建我们真正想要用于碰撞检测的区域。

## 玩家与环境的碰撞

在我们的游戏中，我们将使用 RPG 中经常使用的一种技术；玩家角色将不仅由一个精灵组成，而是由多个精灵叠加而成。这将使我们能够更改角色所穿的盔甲、使用的武器、发型、肤色等，而无需生成所有可能的组合变体。

在我们的游戏中，玩家角色的头像只会使用两张图片：玩家本身和其武器。我们会将它们放入一个组中；这样可以轻松地移动它们。

对于这两个精灵，我们首先会添加一个透明精灵，用于定义与环境碰撞的碰撞区域。下图正是显示了这一点：

![玩家与环境的碰撞](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_09.jpg)

正如你所看到的，我们选择了一个碰撞框，其宽度与玩家角色的身体一样宽，但稍微短一些。这是为了考虑到玩家从下方靠近障碍物的情况。如前图所示，他的头部将隐藏该物体的底部的一部分。通过这个较小的碰撞框，我们自动产生了这种效果。

现在我们不希望角色与级别中的每个元素发生碰撞。例如，它不应该与地面或地面上方的任何东西发生碰撞。

如果你记得，我们之前将级别分成了两个瓦片地图。为了更容易进行碰撞检测，我们将简单地将下面的一个分成两个：

+   包含所有与玩家不发生碰撞的地面元素

+   包含所有与玩家碰撞的元素

这意味着我们现在有三个级别的瓦片地图。

正如你可以想象的，设计这个级别并将所有瓦片添加到正确的瓦片地图中正在变得过于复杂，因为我们手工编写了所有数组。相反，我们将使用瓦片地图编辑器。

### 使用瓦片地图编辑器

有相当多的免费和开源的瓦片地图编辑器。对于这个游戏，我们将使用 Tiled ([`www.mapeditor.org/`](http://www.mapeditor.org/))。它的优点是可以将瓦片地图导出为 JSON 文件。

我们将用于创建级别的图像来自 Mozilla 的游戏 BrowserQuest。以下图片显示了其中的一部分：

![使用瓦片地图编辑器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_10.jpg)

正如你所见，我们有草地的瓦片，沙地的瓦片，以及代表向沙地过渡的瓦片。过渡瓦片是半透明的，一半是沙地。这样可以让我们从任何其他类型的地面过渡到沙地。

这意味着我们将不得不使用另一个瓦片地图。下面的瓦片地图将分成两部分：一个包含所有地面元素，一个包含透明像素且不与玩家发生碰撞的过渡元素。但是，总共我们将有四个瓦片地图来绘制我们的级别。例如，我们级别的一部分带有沙子、草地和一棵树会是这样的：

![使用瓦片地图编辑器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_11.jpg)

我们不会查看导入 Tiled 生成的 JSON 文件的整个代码。如果你想了解更多细节，只需查看`gf.importTiled`函数。重要的部分是我们使用 jQuery 的`$.ajax`函数。使用这个函数，我们将能够加载 JSON 文件。诀窍是使用正确的参数来调用它：

```js
$.ajax({
   url: url,
   async: false,
   dataType: 'json',
   success: function(json){...}
);
```

jQuery 还提供了一个名为`$.getJSON`的简写函数，但是我们希望进行同步调用，这只有通过`$.ajax`才可能。使用这些调用，我们提供给成功参数的函数将在 JSON 文件加载完成后调用。就在这个函数中，我们将导入文件。

如果你想看看我们究竟是如何做到的，你只需简单地查看本章提供的代码即可。

现在我们正在使用`$.ajax`函数，我们只需确保从服务器访问我们的代码以测试它，因为简单地在浏览器中打开我们的 HTML 文件将不再起作用。如果你没有运行服务器，你可以在 Windows 上使用 EasyPHP ([`www.easyphp.org`](http://www.easyphp.org))，或者在 OS X 上使用 MAMP ([`www.mamp.info`](http://www.mamp.info))。

## 玩家与精灵的碰撞

我们只支持一种精灵与精灵碰撞检测：玩家攻击敌人或与 NPC 交谈。和以前一样，我们需要一个透明精灵来定义应该检测到碰撞的区域。但是这次，这个区域不在玩家身上，而是在他前面，如下面的截图所示：

![玩家与精灵碰撞](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_12.jpg)

唯一的技巧是这个区域必须四处移动，以始终面向玩家所看的方向。如果我们使用上一个游戏中用来实现玩家的相同 OO 代码，它看起来会像这样：

```js
var player = new (function(){
    // the group holding both the player sprite and the weapon
    this.div = $();
    // the sprite holding the player's avatar
    this.avatar = $();
    // the sprite holding the weapon
    this.weapon = $();
    // the hit zone
    this.hitzone  = $();
    // collision zone
    this.colzone = $();

    //...

    this.update = function () {
        //...
    };

    this.left = function (){
        if(state !== "strike"){
            if(orientation !== "left" && moveY === 0 && moveX === 0){
                orientation = "left";
                gf.x(this.hitzone, 16);
                gf.y(this.hitzone, 16);
                gf.h(this.hitzone,  128 + 32);
                gf.w(this.hitzone, 64);
                //...

            }
            //...
        }
    };

    this.right = function (){
        //...
    };

    this.up = function (){
        //...
    };

    this.down = function (){
        if(state !== "strike"){
            if(orientation !== "down" && moveY === 0 && moveX === 0) {
                orientation = "down";
                state = "walk";
                gf.x(this.hitzone, 16);
                gf.y(this.hitzone, 192-80);
                gf.w(this.hitzone,  128 + 32);
                gf.h(this.hitzone, 64);
                //...
            }
            //...
        }
    };

    //...
});
```

代码的突出显示部分显示了我们在与 NPC 和敌人的交互中更改碰撞区域位置的地方。我们称之为精灵命中区，因为它代表了玩家剑挥动覆盖的区域。

要为这个击中区选择正确的大小和位置，你确实必须对你使用的图像进行微调。

在主游戏循环中，我们将检查此区域与 NPC 列表和敌人之间的碰撞，然后。

```js
this.detectInteraction = function(npcs, enemies, console){
    if(state == "strike" && !interacted){
        for (var i = 0; i < npcs.length; i++){
            if(gf.spriteCollide(this.hitzone, npcs[i].div)){
                npcs[i].object.dialog();
                interacted = true;
                return;
            }
        }
        for (var i = 0; i < enemies.length; i++){
            if(gf.spriteCollide(this.hitzone, enemies[i].div)){
                // handle combat
                interacted = true;
                return;
            }
        }
    }
};
```

### 与 NPC 交谈

我们将实现与 NPC 的唯一交互是单向对话。当玩家击中 NPC 时，我们将显示一行对话。如果他再次击中它，并且 NPC 还有更多话要说，我们将显示下一行对话。

我们将在屏幕底部使用一行来显示这个文本。这行必须是半透明的，以便让玩家看到其背后的关卡，并且必须覆盖游戏的所有元素。这是我们将创建它的方法：

```js
container.append("<div id='console' style='font-family: \"Press Start 2P\", cursive; color: #fff; width: 770px; height: 20px; padding: 15px; position: absolute; bottom: 0; background: rgba(0,0,0,0.5); z-index: 3000'>");
```

这种类型的界面通常称为控制台。为了使其半透明，同时保留其中的文本不透明，我们通过调用`rgba()`函数应用透明的背景颜色。为了确保它浮在所有游戏元素的上方，我们给它一个足够大的 z 索引。

要在此控制台中显示文本，我们只需使用`.html()`。以下代码是 NPC 的完整实现：

```js
var NPC = function(name, text, console){
    var current = 0;

    this.getText = function(){
        if(current === text.length){
            current = 0;
            return "[end]";
        }
        return name + ": " + text[current++];
    };

    this.dialog = function(){
        console.html(this.getText());
    }
}
```

这是我们将实例化其中一个的方法：

```js
npcs.push({
    div: gf.addSprite(npcsGroup,"NPC1", {
        x:      800,
        y:      800,
        width:  96,
        height: 96
    }),
    object: new NPC("Dr. Where", ["Welcome to this small universe...","I hope you will enjoy it.","You should head east from here...","there's someone you may want to meet."], console)
});
npcs[npcs.length-1].object.div = npcs[npcs.length-1].div;
gf.setAnimation(npcs[npcs.length-1].div, new gf.animation({
    url: "npc/scientist.png"
}));
$("#NPC1").css("z-index",800 + 96);
```

这里没有什么特别的；我们只需确保设置正确的 z 索引即可。

### 与敌人战斗

要与敌人战斗，我们将模拟掷骰子。战斗规则在 RPG 中非常典型：玩家向玩家掷骰子，并将其加到一个称为攻击修正值的固定值上。这将生成玩家攻击的攻击值。敌人将试图通过向敌人掷骰子并将其加到自己的防御修正值上来进行防御。

如果玩家的攻击大于敌人的防御，攻击就成功了，敌人将受到等于玩家攻击的生命损失。如果敌人的防御更强，攻击将失败，敌人将保持安全。

以下代码是此机制的实现：

```js
if(gf.spriteCollide(this.hitzone, enemies[i].div)){
    var enemyRoll = enemies[i].object.defend();
    var playerRoll = Math.round(Math.random() * 6) + 5;

    if(enemyRoll <= playerRoll){
        var dead = enemies[i].object.kill(playerRoll);
        console.html("You hit the enemy "+playerRoll+"pt");
        if (dead) {
            console.html("You killed the enemy!");
            enemies[i].div.fadeOut(2000, function(){
                $(this).remove();
            });
            enemies.splice(i,1);
        }
    } else {
        console.html("The enemy countered your attack");
    }
    interacted = true;
    return;
}
```

在这里，我们使用控制台向玩家显示战斗的进展情况。战斗的公式可能会因额外的参数而不同，例如玩家使用的武器提供的奖励以及敌人的盔甲。当决定一次打击是否成功时，真的取决于你要考虑的因素。

我们没有实现这个，但是敌人的反击会完全相同。

# 完整的游戏

游戏就到此为止了。其余的所有实现都直接来自我们在第四章中创建的游戏，《横向观察》。我们使用相同的面向对象的代码来解决玩家和其他精灵之间的碰撞。

一个很好的练习是让敌人四处移动并攻击玩家，为玩家实现一个经验和生命条，并设计一个更大的世界和更多的 NPC，使故事更加有趣。事实上，这就是编写 RPG 游戏的伟大之处；它们是讲故事的绝佳媒介！

另一种你可以改进这个游戏的方式是使用等距投影而不是正交投影。解释如何编写一个通用的等距引擎不在本书的范围内，但如果你想了解更多，你可以阅读*Andres Pagella*的《使用 HTML5、CSS3 和 JavaScript 制作等距社交实时游戏》（[`shop.oreilly.com/product/0636920020011.do`](http://shop.oreilly.com/product/0636920020011.do)）。

# 等距瓷砖

处理等距瓷砖时存在两个困难。首先，使用 DOM 元素显示正交网格非常简单，而使用等距网格更加复杂。其次，遮挡计算更加困难。

## 绘制等距瓷砖地图

我们将在这里使用一个技巧来生成我们的瓷砖地图。我们的每个瓷砖都将存储在一个区域，周围都是透明像素，以便给它们一个方形的形状，就像以下的屏幕截图一样：

![绘制等距瓷砖地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_13.jpg)

要实现这种魔法效果，我们将使用两个普通的瓷砖地图来显示一个等距瓷砖地图。它们会重叠，但它们之间的偏移量等于一个瓷砖的高度和宽度的一半。下图展示了它会是什么样子：

![绘制等距瓷砖地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_05_14.jpg)

## 等距游戏的遮挡

对于等距游戏来说，遮挡比正交游戏更难管理。在这种情况下，你不能简单地通过图层来生成正确的遮挡。相反，你将不得不给在关卡中定位的每个“块”（如墙壁、树木、物体等）赋予一个 z 索引。

这种遮挡的价值将取决于其坐标，就像之前的玩家、NPC 和敌人一样。这意味着你需要对瓦片地图进行后处理并生成它们。这个过程可能非常复杂，难以自动化，如果你的游戏元素数量相对较小，你可能会选择手动完成。否则，你将需要一些关于每个块位于何处的 3D 模型。

# 摘要

在本章中，你已经学会了如何充分利用瓦片地图。现在你可以使用本章和上一章学到的技术来编写各种各样的游戏。你可能会发现，在编写游戏时遇到的问题往往是相同的。然而，最佳解决方案往往取决于你游戏的限制和约束。

当你开始编写游戏时，不要试图实现通用解决方案，而是首先专注于你的特定情况。结果很可能会更快、更容易维护，并且实现起来会花费更少的时间。

在下一章中，我们将学习如何使用我们在第四章 *横向看* 中创建的平台游戏来实现多层游戏。


# 第六章：向你的游戏添加关卡

到目前为止，我们所有的游戏都只有一个关卡。这对于演示或概念验证来说很好，但你可能希望在游戏中有很多关卡。和往常一样，有很多方法可以做到这一点，但其中大多数都基于这样一个想法：每个关卡都由它们自己的文件（或文件）描述。

我们将在本章开始时快速探讨不同的文件组合方式来创建你的游戏。然后我们将查看允许这种技术的 jQuery 函数。

最后，我们将把我们在第四章中开发的游戏，*横向查看*，扩展到包括三个关卡，通过实现之前描述的一些技术。

以下是本章我们将涵盖的主题的快速列表：

+   使用多个文件来构建你的游戏

+   使用 `$.ajax` 加载文件

+   执行远程 JavaScript

+   向我们的游戏添加新关卡

# 实现多文件游戏

你首先要问自己的问题是，“其他文件何时加载？” 传统的方法是有简单的关卡，并在前一个关卡结束时加载下一个。这是平台游戏的典型情景。

另一种方法是有一个大的关卡，并在到达给定点时加载子关卡。通常，在 RPG 中，大关卡将是外部世界，而子关卡将是建筑物内部。在这两个示例中，文件的加载不需要异步执行。

最后一个常见的方法是拥有一个由许多子关卡组成的单个非常大的关卡。这通常是 MMORPG 的情况。在这里，你需要异步加载文件，以便玩家不会注意到必须加载子关卡。

你将面临的挑战取决于你处于上述哪种情况。它们可以分为以下几类：加载瓦片地图、精灵、加载逻辑行为。

## 加载瓦片地图

如果你还记得，在第五章中，*透视*，我们加载了以 JSON 文件形式的瓦片地图。正如我们之前解释的那样，我们加载一个包含瓦片地图描述的 JSON 文件。为此，我们使用 jQuery 中的基本 AJAX 函数：`$.ajax()`。稍后我们将看到如何使用此函数的所有细节。

然而，仅仅加载瓦片地图通常不足以完全描述你的关卡。你可能想要指定关卡结束的位置，哪些区域会杀死玩家，等等。一种常见的技术是使用第二个瓦片地图，一个不可见的瓦片地图，它包含为另一个瓦片地图添加含义的瓦片。

以下图示是一个示例：

![加载瓦片地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_06_01.jpg)

这有几个优点：

+   你可以轻松地给不同的瓦片赋予相同的语义含义。例如，有或没有草的瓦片可以表示地面，并且与玩家的交互方式完全相同。

+   您可以为使用完全不同瓦片集的两个级别的瓦片赋予相同的语义含义。这样，只要它们使用相同的逻辑瓦片来建模，您就不必真正担心在您的级别中使用了什么图像。

实现这并不是真正困难的。下面的代码显示了`gf.addTilemap`函数的更改：

```js
gf.addTilemap = function(parent, divId, options){
    var options = $.extend({
        x: 0,
        y: 0,
        tileWidth: 64,
        tileHeight: 64,
        width: 0,
        height: 0,
        map: [],
        animations: [],
        logic: false
    }, options);

    var tilemap = gf.tilemapFragment.clone().attr("id",divId).data("gf",options);

    if (!options.logic){

       // find the visible part
       var offset = gf.offset(parent);
       var visible = gf.tilemapBox(options, {
          x:      -options.x - offset.x,
          y:      -options.x - offset.y,
          width:  gf.baseDiv.width(),
          height: gf.baseDiv.height()
       });
         options.visible = visible;

       //create line and row fragment:
       for (var i=visible.y1; i < visible.y2; i++){
           for(var j=visible.x1; j < visible.x2; j++) {
               var animationIndex = options.map[i][j];

               if(animationIndex > 0){
                   var tileOptions = {
                       x: options.x + j*options.tileWidth,
                       y: options.y + i*options.tileHeight,
                       width: options.tileWidth,
                       height: options.tileHeight
                   }
                   var tile = gf.spriteFragment.clone().css({
                       left:   tileOptions.x,
                       top:    tileOptions.y,
                       width:  tileOptions.width,
                       height: tileOptions.height}
                   ).addClass("gf_line_"+i).addClass("gf_column_"+j).data("gf", tileOptions);

                   gf.setAnimation(tile, options.animations[animationIndex-1]);

                   tilemap.append(tile);
               }
           }
       }
    }
    parent.append(tilemap);
    return tilemap;
}
```

如您所见，我们只是添加了一个标志来指示瓦片地图是否是为了逻辑目的。如果是这样，我们就不需要在其中创建任何瓦片。

碰撞检测函数现在也略有修改。在逻辑瓦片地图的情况下，我们不能简单地返回 divs。相反，我们将返回一个包含碰撞瓦片的大小、位置和类型的对象文字。下面的代码片段显示了这一点：

```js
gf.tilemapCollide = function(tilemap, box){
    var options = tilemap.data("gf");
    var collisionBox = gf.tilemapBox(options, box);
    var divs = []

    for (var i = collisionBox.y1; i < collisionBox.y2; i++){
        for (var j = collisionBox.x1; j < collisionBox.x2; j++){
            var index = options.map[i][j];
            if( index > 0){
               if(options.logic) {
 divs.push({
 type:   index,
 x:      j*options.tileWidth,
 y:      i*options.tileHeight,
 width:  options.tileWidth,
 height: options.tileHeight
 });
 } else {
                   divs.push(tilemap.find(".gf_line_"+i+".gf_column_"+j));
             }
            }
        }
    }
    return divs;
}
```

一旦实现了这个功能，加载关卡就变得非常容易了。事实上，只要逻辑瓦片地图存在并且游戏代码知道如何对每个瓦片做出反应，我们就不需要任何额外的东西让玩家对其环境做出反应。

## 加载精灵及其行为

如果从不同文件加载瓦片地图相当简单，那么对于关卡包含的精灵，有很多方法可以做同样的事情。

您可以为一个 JSON 文件实现一个解释器，该解释器将依次创建和配置敌人和 NPC。这样做的好处是，您可以合并这个 JSON 和描述瓦片地图的 JSON。这样您只需要加载一个文件而不是两个文件。由于每个加载的文件都有相当大的开销，因此文件的大小几乎没有影响；在大多数情况下，它将使您的关卡加载更快。下图说明了这一点：

![加载精灵及其行为](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_06_02.jpg)

它也有一些缺点：首先，您的引擎必须被编写成理解您希望您的敌人采取的所有可能行为。这意味着，如果您有一种仅在游戏的第十关中使用的敌人，您仍然需要在启动时加载其实现。如果您在一个团队中工作，其他成员想要实现自己类型的敌人，他们将需要修改引擎而不仅仅是在他们的关卡上工作。

您还需要非常小心地指定一个涵盖所有需求的 JSON 格式，否则您将有可能在以后不得不重构游戏的大部分内容。下面的代码是这样一个 JSON 文件的示例：

```js
{
   "enemies" : [
      {
         "name" : "Monster1",
         "type" : "spider",
         "positionx" : 213,
         "positiony" : 11,
         "pathx" : [250,300,213],
         "pathy" : [30,11,11]
      },
      {
         "name" : "Monster2",
         "type" : "fly",
         "positionx" : 345,
         "positiony" : 100,
         "pathx" : [12,345],
         "pathy" : [100,100]
      }   
   ],
   "npcs" : [
      {
         "name" : "Johny",
         "type" : "farmer",
         "positionx" : 202,
         "positiony" : 104,
         "dialog" : [
            "Hi, welcome to my home,",
            "Feel free to wander around!"
         ]
      }
   ]
}
```

另一种可能的实现是加载一个完整的脚本，该脚本将依次创建敌人并配置它们。这样做的好处是使您的游戏更具模块化，并减少了游戏与关卡之间的耦合。

虽然它有一些缺点。首先，如果你不小心，你的级别代码有可能覆盖一些主要游戏变量。这将创建相当难以跟踪的错误，并且将依赖于级别加载的顺序。其次，你必须特别小心地选择你的变量范围，因为每次加载新级别的代码都是在全局范围内执行的。

在本章中给出的示例中，我们将选择第二种解决方案，因为对于一个小游戏来说，这是比较合理且相当灵活的。

无论你选择实现哪一个，你很可能将使用`$.ajax`或其别名之一。在下一节中，我们将对其进行详细介绍。

## 使用`$.ajax`

`$.ajax`函数是一个非常强大但低级的函数。它有许多别名，可用于不同的特定任务：

+   `$.get`是一个多用途别名，与`$.ajax`相比减少了选项的数量，并且其 API 是基于多个可选参数而不是单个对象文字。它总是以异步方式加载文件。

+   `$.getJSON`是一个用于异步加载 JSON 文件的函数。

+   `$.getScript`是一个以异步方式加载脚本并且执行的函数。

+   `$.load`是一个以异步方式加载 HTML 文件并将其内容注入到所选元素中的函数。

+   `$.post`类似于`$.get`，但使用了 post 请求。

如你所见，所有这些别名都有一个共同点：它们都以异步方式加载它们的文件。这意味着如果您更喜欢同步加载资源，您将需要使用`$.ajax`。但是，一旦您知道了正确的参数，你稍后会看到它实际上并没有比别名更复杂。此外，别名的 API 文档始终包括要用于`$.ajax`调用的确切参数以产生相同的效果。

当使用`$.ajax`时，你必须确保通过服务器访问文件，并且遵守同源策略。否则，在大多数浏览器上，你可能会遇到问题。要了解有关`$.ajax`的更多信息，您应该查看官方 jQuery API 文档（[`api.jquery.com/jQuery.ajax/`](http://api.jquery.com/jQuery.ajax/)）。

## 加载一个 JSON 文件

JSON 文件是一种非常方便的加载外部数据的方式，无需自行解析。一旦加载，JSON 文件通常存储在一个简单的 JavaScript 对象中。然后你只需查找其属性就能访问数据。

如果你想用`$.ajax`模拟对`$.getJSON`的调用，它看起来会像下面的代码：

```js
$.ajax({
  url: url,
  dataType: 'json',
  data: data,
  success: callback
});
```

在这里，`url`是 JSON 文件的 Web 地址，`data`是您可能希望传递到服务器的可选参数列表，`success`是在加载 JSON 文件后将处理它的回调函数。如果你想同步访问远程文件，你必须在调用中添加参数`async` `:` `false`。

它是在回调函数中你将决定如何处理 JSON 文件；它将具有以下签名：

```js
var callback = success(data, textStatus, jqXHR)
```

在这里，`data`保存着从 JSON 文件生成的对象。你将如何处理它，这实际上取决于你的用例；这里是一个导入 Tiled 生成的地图图块的代码的简短版本：

```js
success: function(json){
    //...

   var layers = json.layers;
   var usedTiles = [];
   var animationCounter = 0;
   var tilemapArrays = [];

   // Detect which animations we need to generate
   // and convert the tiles array indexes to the new ones
   for (var i=0; i < layers.length; i++){
      if(layers[i].type === "tilelayer"){
         // ...
         tilemapArrays.push(tilemapArray);
      }
   }
   // adding the tilemaps
   for (var i=0; i<tilemapArrays.length; i++){
      tilemaps.push(gf.addTilemap(parent, divIdPrefix+i, {
         x:          0,
         y:          0,
         tileWidth:  tileWidth,
         tileHeight: tileHeight,
         width:      width,
         height:     height,
         map:        tilemapArrays[i],
         animations: animations,
         logic: (layers[i].name === "logic")
         }));
      }
   }
});
```

高亮部分是相当典型的。实际上，大多数复杂的 JSON 都将包含一系列元素，以便描述任意数量的类似实体。当您不是 JSON 文件规范的设计者时，您可能会发现自己处于这样一种情况：您必须将 JSON 对象的内容转换为自己的数据结构。这段代码正是这样做的。

这里没有通用的方法，你真的必须考虑每种情况。好处是，在大多数情况下，这段代码只会在游戏中执行几次，因此，性能方面并不敏感。与其在所有地方搜索可以使其运行更快的地方，还不如使其尽可能易读。

## 加载远程脚本

如果你想要用`$.ajax`来模仿`$.getScript`的用法，看起来会像下面这样：

```js
$.ajax({
  url: url,
  dataType: "script",
  success: success
});
```

就像我们之前做的那样，你可以通过简单地将`async : false`添加到参数列表中使其同步。这将做两件事情：加载脚本并执行它。这里回调函数并不那么重要，它只允许你跟踪文件是否成功检索。

正如前面提到的，脚本将在全局范围内执行。这对你的代码组织有一些影响。直到现在，我们游戏的代码看起来像这样：

```js
$(function() {
    var someVariable = "someValue";

    var someFunction = function(){
        //do something
    }
});
```

所有的函数和变量都在一个"私有"范围内定义，外部无法访问。这意味着如果你的远程代码尝试做下面这样的事情，它将失败：

```js
var myVariable = someVariable;
someFunction();
```

实际上，函数`someFunction`和`someVariable`在全局范围内是不可见的。解决方案是仔细选择哪些变量和函数应该对远程代码可见，并将它们放在全局范围内。在我们的情况下，可能会像这样：

```js
var someVariable = "someValue";    
var someFunction = function(){
    //do something
}

$(function() {
    // do something else
});
```

你可能想要将所有这些函数都放在一个命名空间中，就像我们为我们的框架所做的那样。由于你正在编写一个最终产品，不太可能被其他库用作库，这更多取决于个人偏好。

## 调试对$.ajax 的调用

现在我们正在加载远程文件，可能会出现一系列新问题：文件的 URL 可能不再有效，服务器可能已经关闭，或者文件可能格式不正确。在生产环境中，您可能希望在运行时检测这些问题，以向用户显示一条消息，而不仅仅是崩溃。在开发阶段，您可能希望找出到底出了什么问题，以便调试您的代码。

jQuery 提供了三个函数，你可以用它们来实现这个功能：.`done()`、`.fail()`和`.always()`。以前还有另外三个函数（`.success()`、`.error()`和`.complete()`），但自 jQuery 1.8 版本起已经被弃用。

### .done()

`.done()`可以用来代替成功回调。只有在文件成功加载后才会调用它。提供的函数将按以下顺序调用以下三个参数：`data`、`textStatus`、`jqXHR`。

`data`是加载的文件，这意味着如果你愿意，你可以在那里处理你的 JSON 文件。

### `.fail()`

每当发生问题时都会调用`.fail()`。提供的函数将按以下顺序调用以下三个参数：`jqXHR`、`textStatus`、`exception`。

当加载和执行脚本时，如果脚本未被执行，查找发生了什么非常方便。实际上，在大多数浏览器的调试控制台中不会出现异常，但异常参数将包含你的代码抛出的确切异常。

例如，如果我们看一下之前描述的作用域问题，主游戏包含以下代码：

```js
$(function() {
    var someVariable = "someValue";

    var someFunction = function(){
        //do something
    }
});
```

远程脚本如下：

```js
someFunction();
```

你可以通过编写以下代码来捕获异常：

```js
$.getScript("myScript.js").fail(function(jqxhr, textStatus, exception) {
    console.log("Error: "+exception);
});
```

控制台将写入以下错误：

```js
error: ReferenceError: someFunction is not defined
```

这将用于检测其他问题，如服务器无响应等。

# 修改我们的平台游戏

现在我们已经掌握了创建多级游戏所需的所有知识。首先，我们将创建一个级别列表和一个加载它们的函数：

```js
var levels = [
        {tiles: "level1.json", enemies: "level1.js"},
        {tiles: "level2.json", enemies: "level2.js"}
    ];

    var currentLevel = 0;

    var loadNextLevel = function(group){
        var level = levels[currentLevel++];
        // clear old level
        $("#level0").remove();
        $("#level1").remove();
        for(var i = 0; i < enemies.length; i++){
            enemies[i].div.remove();
        }
        enemies = [];

        // create the new level

        // first the tiles
        gf.importTiled(level.tiles, group, "level");

        // then the enemies
        $.getScript(level.enemies);

        // finaly return the div holdoing the tilemap
        return $("#level1");
    }
```

高亮显示的行是远程加载文件的行。这使用了之前描述的函数。正如你所看到的，没有机制来检测游戏是否结束。如果你愿意，你可以将其作为作业添加进去！

在加载下一级之前，我们必须确保删除现有的级别以及它包含的敌人。

现在我们将更改游戏以使用逻辑砖块而不是标准砖块。这样我们可以有一种定义一个级别结束的砖块。以下是我们修改后用于执行此操作的碰撞检测代码：

```js
var collisions = gf.tilemapCollide(tilemap, {x: newX, y: newY, width: newW, height: newH});
var i = 0;
while (i < collisions.length > 0) {
    var collision = collisions[i];
    i++;
    var collisionBox = {
        x1: collision.x,
        y1: collision.y,
        x2: collision.x + collision.width,
        y2: collision.y + collision.height
    };

    // react differently to each kind of tile
    switch (collision.type) {
        case 1:
            // collision tiles
            var x = gf.intersect(newX, newX + newW, collisionBox.x1,collisionBox.x2);
            var y = gf.intersect(newY, newY + newH, collisionBox.y1,collisionBox.y2);

            var diffx = (x[0] === newX)? x[0]-x[1] : x[1]-x[0];
            var diffy = (y[0] === newY)? y[0]-y[1] : y[1]-y[0];
            if (Math.abs(diffx) > Math.abs(diffy)){
                // displace along the y axis
                 newY -= diffy;
                 speed = 0;
                 if(status=="jump" && diffy > 0){
                     status="stand";
                     gf.setAnimation(this.div, playerAnim.stand);
                 }
            } else {
                // displace along the x axis
                newX -= diffx;
            }
            break;
        case 2:
            // deadly tiles
            // collision tiles
            var y = gf.intersect(newY, newY + newH, collisionBox.y1,collisionBox.y2);
            var diffy = (y[0] === newY)? y[0]-y[1] : y[1]-y[0];
            if(diffy > 40){
                status = "dead";
            }
            break;
        case 3: 
 // end of level tiles
 status = "finished"; 
 break;
    }

}
```

如你所见，我们增加了玩家碰到某些砖块时死亡的可能性。这将使他/她重新出现在当前级别的开始处。如果砖块的类型是 3，我们将玩家的状态设置为`finished`。稍后，我们检测状态并加载下一个级别。

```js
if (status == "finished") {
    tilemap         = loadNextLevel(group);
    gf.x(this.div, 0);
    gf.y(this.div, 0);
    status = "stand";
    gf.setAnimation(this.div, playerAnim.jump);
}
```

别忘了重置玩家位置，否则它将出现在下一级的中间位置，而不是起始点。

现在我们必须编写每个脚本，为它们各自的级别创建敌人。这几乎是与游戏的先前版本中使用的相同代码，但放在一个单独的文件中：

```js
var group = $("#group");

var fly1   = new Fly();
fly1.init(
    gf.addSprite(group,"fly1",{width: 69, height: 31, x: 280, y: 220}),
    280, 490,
    flyAnim
);
enemies.push(fly1);

var slime1 = new Slime();
slime1.init(
    gf.addSprite(group,"slime1",{width: 43, height: 28, x: 980, y: 392}),
    980, 1140,
    slimeAnim
);
enemies.push(slime1);

var slime2 = new Slime();
slime2.init(
    gf.addSprite(group,"slime2",{width: 43, height: 28, x: 2800, y: 392}),
    2800, 3000,
    slimeAnim
);
enemies.push(slime2);
```

正如你可能已经想到的那样，我们不能简单地运行游戏并使用该脚本而不对我们的代码进行一些修改。如前所述，远程脚本将在全局范围内执行，我们需要将它使用的部分移到其中。

在这里，我们需要敌人的对象和动画，以及包含敌人列表的数组。我们将它们从它们的闭包中取出，然后添加到我们游戏脚本的开头：

```js
var enemies = [];
var slimeAnim = {
    stand: new gf.animation({
        url: "slime.png"
    }),
    // ...

}
var flyAnim = {
    stand: new gf.animation({
        url: "fly.png"
    }),
    // ...}

var Slime = function() {
    // ...
};
var Fly = function() {}
Fly.prototype = new Slime();
Fly.prototype.dies = function(){
    gf.y(this.div, gf.y(this.div) + 5);
}

$(function() {
   // here come the rest of the game
});
```

现在游戏将包含我们想要的任意数量的关卡。享受关卡编辑器的乐趣！在这里，我们仅使用脚本来设置敌人，但如果我们想的话，我们也可以用它来更改关卡背景。

# 摘要

使你的游戏多层级将为你带来一些新的技巧。现在你已经学会了将你的资产分成许多文件，并在需要时加载它们。你还学会了如何使用瓦片来描述逻辑行为，而不仅仅是你的关卡的图形方面。

正如前面提到的，游戏还有很多可以做得更有趣的地方。我建议花一些时间来设计关卡。在大多数商业游戏中，这是花费时间最多的地方，所以不要犹豫，停下编码一段时间，开始制作和测试你的关卡！

在下一章中，你将学习如何制作多人游戏。为此，我们将使用我们在第五章中创建的游戏，*将事情放在透视中*，并以与我们在本章中使用的第四章中的游戏相同的方式为它添加新功能。


# 第七章：制作多人游戏

单人游戏是有趣的，正如我们已经看到的，你可以使用 JavaScript 制作各种不同类型的单人游戏。然而，让游戏在网络浏览器中运行，就会有一种很大的诱惑，让它成为多人游戏。这正是我们在本章中要做的，而且什么比一个 MMORPG 更好的多人游戏示例呢！

我们将把我们在第五章中的小型单人 RPG，*将事物置于透视之下*，变成一个全新的 MMORPG：*阿尔皮吉的世界*。

然而，首先需要警告一下——我们将用来实现游戏服务器端的技术是 PHP + MySQL。这么做的原因是它迄今为止是最常见的技术。如果你有某种类型的托管服务，很可能会直接支持它。

有许多原因说明这不一定是最佳解决方案。当编写一个游戏，其中服务器端的使用不仅仅是为了提供静态页面时，你必须仔细考虑扩展问题：

+   有多少用户能够同时在你的系统上玩？

+   当玩家数量超过这个限制时，你将怎么办？

+   你准备付多少费用来使你的服务器运行？

+   你想向玩家提供什么样的服务质量？

回答这些问题应该决定你将选择什么技术和基础架构。本书的目的不在于详细讨论这一点；我们将实现的解决方案应该可以扩展到几十名玩家而没有任何问题，但你所学到的技术可以应用于任何你选择的软件解决方案或托管服务！

在本章中，我们将涵盖以下主题：

+   多人游戏规范

+   管理玩家账户

+   同步玩家状态

+   管理敌人的服务器端

# 阿尔皮吉的世界

我们将基于我们之前的 RPG 创造的游戏将具有以下特点：

+   一个玩家可以创建一个账户，并用它登录游戏

+   当他们回到游戏时，他们的化身将会重新出现在他们离开时的位置

+   每个玩家都可以看到同时在线的所有其他玩家

+   其他玩家的名字将显示在他们的头像上方

+   敌人的状态由服务器端管理：如果有人杀死一个怪物，那么对于所有其他玩家来说，它将会死亡

这个游戏将具有与其基础游戏相同的一些限制。怪物不会反击，也不会四处移动。

# 管理玩家账户

让我们从基础知识开始：让玩家创建账户并登录游戏。为了在服务器端存储信息，我们将使用一个数据库（MySQL）。我们将使用的表结构非常简单，因为没有太多需要存储的东西。玩家的账户将存储在一个我们会有创意地称为`players`的表中。

这个表将具有以下行：

+   NAME: 这是一个包含玩家姓名的字符串。它将是唯一的，因此没有两个玩家可以拥有相同的名字。

+   PW：这是一个字符串，保存着玩家的密码。它被哈希化了（关于这点，*在数据库中搜索元素* 中有更多内容）。

+   X：这是一个双精度浮点数，将保存玩家的 x 坐标。

+   Y：这是一个双精度浮点数，将保存玩家的 y 坐标。

+   DIR：这是一个整数，我们将用来存储玩家面向的方向。

+   STATE：这是一个整数，表示玩家的状态：站立、行走或战斗。

+   LASTUPDATE：这是一个时间戳，记录了服务器最后一次收到玩家消息的时间。

提供了一个 SQL 脚本，该脚本在文件 `create_tables.sql` 中创建了游戏所需的所有表格。

为了创建允许创建账户或登录游戏的用户界面，我们将使用一系列会重叠游戏屏幕的`div`。任何时候只有一个会是可见的。以下图展示了可能的用户交互和相应的屏幕：

![管理玩家账户](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_07_01.jpg)

这些屏幕中的每一个都将是一个包含几个输入字段和/或按钮的`div`。例如，允许玩家创建账户的屏幕将是：

```js
<div id="create" class="screen">
   <h1>Create an account</h1>
   <div class="input"><span>name:</span><input id="create-name" type="text" /></div>
   <div class="input"><span>pw:</span><input id="create-pw" type="text" /></div>
   <a class="button left" id="create-cancel" href="#">cancel</a>
   <a class="button right" id="create-create" href="#">create</a>
</div>
```

它将用 CSS 进行样式化，交互部分将用 jQuery 编写。对于这个屏幕，代码如下：

```js
$("#create-cancel").click(function(e){
   $("#create").css("display","none");
   $("#login").css("display","block");
   e.preventDefault();
});
$("#create-create").click(function(e){
   // interact with the server
   e.preventDefault();
});
```

用于将 JavaScript 代码连接到 HTML 代码的链接的 ID 已经突出显示。没什么太复杂的，但是起到了作用。

在前面的代码中故意略去了有趣的部分，即与服务器的实际交互。我们客户端（在浏览器中运行的游戏）与服务器之间的所有交互都将使用 JSON 和我们在上一章中提到的`$.getJSON`函数进行（这是`$.ajax`的简写）。

为了将信息传输到服务器，我们将使用`$.getJSON`函数的第二个参数。为了向客户端传输信息，服务器将生成一个 JSON 文件。

我们将使用服务器端文件来创建一个名为 `createUser.php` 的账户，因此`$.getJSON`调用将如下所示：

```js
$.getJSON(
   "createUser.php",
   {
 name: $("#create-name").val(),
 pw: $("#create-pw").val()
 },
   handleCreateUserJson
)
```

正如我们之前提到的，我们通过将用户选择的名称和密码包装在一个对象文字中，并将其作为第二个参数传递给函数调用来提交它们。正如已经提到的，第三个参数是一个函数，一旦服务器返回它，就会处理 JSON 文件。

## 在数据库中搜索元素

第一次，我们将不得不生成一个 JSON 文件。这个文件非常简单；它应该告诉客户端账户创建是否成功，如果成功，还有关于玩家的信息。

我们选择将其写成以下代码片段，但是如何创建 JSON 文件是完全由您决定的。如果您对 JSON 文件应该遵循的确切语法不熟悉，请快速阅读 [`www.json.org/`](http://www.json.org/)。

```js
{
   "success" : true,
   "x" : 510, 
   "y" : 360, 
   "dir" : 0
}
```

实现函数以读取该 JSON 文件并相应地做出反应非常容易。如果操作成功，我们将启动游戏，并在出现问题时显示错误消息。以下代码就是这样做的：

```js
var handleCreateUserJson = function(json,status){
   if (json.success){
      name = $("#create-name").val();
      initialPlayerPos.x   = json.x;
      initialPlayerPos.y   = json.y
      initialPlayerPos.dir = json.dir;
      $("#create").css("display","none");
      gf.startGame(initialize);
   } else {
      alert("Name already taken!");
   }
}
```

这相当简单，因为大部分复杂的工作都在服务器上运行。让我们看看在那里需要做什么。首先，我们必须检索客户端发送的参数。由于我们使用了`$.getJSON`，对 JSON 文件的请求是一个`GET`请求。这意味着我们将使用 PHP 的`$_GET`超全局变量来访问它们。当向服务器传递敏感信息时，你可能希望使用`POST`请求代替（尽管仅靠这一点并不能阻止有动机的人仍然访问参数）。`$_GET`是一个保存客户端发送的所有参数的变量，因此在我们的情况下，我们可以写成：

```js
$name = $_GET['name'];
$pw    = $_GET['pw'];
```

我们将把用户选择的名称和密码存储到变量中。现在我们必须查询数据库，检查是否已经定义了一个具有此名称的用户。要在 PHP 中运行 SQL 查询，我们将使用 mysqli ([`php.net/manual/en/book.mysqli.php`](http://php.net/manual/en/book.mysqli.php))：

```js
// 1) contect to the DB server
$link = mysqli_connect('localhost', 'username', 'password'); 

// Select the DB
mysqli_select_db($link, 'rpg');

// query the DB
$result = mysqli_query($link, 'SELECT * FROM players WHERE name = "'.$name.'"');
```

### 注意

请注意，上述代码不应用于生产，因为我们直接将用户提供的参数插入到数据库查询中，这会带来巨大的 SQL 注入风险！最佳做法是在将它们注入到 SQL 查询之前始终转义所有字符串。一个简单的方法是使用`mysqli_escape` ([`www.php.net/manual/en/mysqli.real-escape-string.php`](http://www.php.net/manual/en/mysqli.real-escape-string.php))。

我们不会详细介绍编写 SQL 查询的细节。它们很容易阅读，并且对于像这样的基本查询来说，编写也很容易。如果你想了解更多关于 SQL 的知识，你可以搜索网络或阅读关于该主题的众多书籍之一。

一旦我们得到了查询结果，我们需要检查查询是否返回了一个元素，以查看该名称是否已经存在于数据库中。这只需简单地执行：

```js
$obj = mysqli_fetch_object($result);
```

现在，如果`$obj`为零，我们可以创建新账户。

## 在数据库中创建一个新玩家

在查看将在数据库中创建玩家的查询之前，让我们谈谈密码。你永远不应该在数据库中存储原始密码，因为历史表明数据库经常遭到黑客攻击。推荐的解决方案是在存储密码之前对其进行哈希处理。然后，你可以简单地将提交的密码的哈希版本与数据库中存储的密码进行比较。

![在数据库中创建一个新玩家](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_07_02.jpg)

这就是我们将用 PHP 的`hash`函数来做的事情。然后我们将简单地将用户名和哈希值与玩家的起始位置一起插入到数据库中。

由于这也是一个查询，我们使用了与之前用来查找账户是否已经存在这个名称相同的函数：

```js
$hash = hash('md5', $pw);
$query = 'INSERT INTO players (name, x, y, dir, pw, state) VALUES("'.$name.'", 510, 360, 0, "'.$hash.'", 0)';
mysqli_query($link, $query);
```

我们传递给`hash`函数的第一个参数在前面的代码中被突出显示了。它是哈希方法，我们在这里使用的`'md5'`现在不推荐用于生产，因为它被认为现在太容易被破解。如果你想了解更多可用的方法，请查看[`www.php.net/manual/en/function.hash.php`](http://www.php.net/manual/en/function.hash.php)中的函数文档。

现在我们可以生成客户端将接收的 JSON 了。这是通过使用 PHP 的`json_encode`函数完成的（[`php.net/manual/en/function.json-encode.php`](http://php.net/manual/en/function.json-encode.php)）。这个函数接受一个对象并将其转换为 JSON 格式的字符串。

```js
$json['success'] = true;
$json['x'] = 510;
$json['y'] = 360;
$json['dir'] = 0;

echo json_encode($json);
```

现在，为了让你对客户端文件的整体情况有个全局了解，完整的代码如下所示：

```js
<?php
   session_start();

   include 'dbconnect.php';

    // JSON Object 
    $json = array('success'=>false);

   $name = $_GET['name'];
   $pw    = $_GET['pw'];

   if(isset($name) && isset($pw)) {
      $hash = hash('md5', $pw);
      $query = 'SELECT * FROM players WHERE name = "'.$name.'"';
      $result = mysqli_query($link, $query);
      $obj = mysqli_fetch_object($result);
      if(!$obj){
         $query = 'INSERT INTO players (name, x, y, dir, pw, state) VALUES("'.$name.'", 510, 360, 0, "'.$hash.'", 0)';
         $result = mysqli_query($link, $query);

         $_SESSION['name'] = $name;
         $_SESSION['pw'] = $pw;

            $json['success'] = true;
            $json['x'] = 510;
            $json['y'] = 360;
            $json['dir'] = 0;
      }
   }

    echo json_encode($json);

   // Close DB's connection
   mysqli_close($link);
?>
```

在这里，你可以看到我们包含了一个名为`dbconnect.php`的文件，它允许我们在此文件中只写一次数据库配置，并从需要连接到它的每个文件中使用它。这是我们将用于实现服务器端的每个其他功能的同一个基本功能。

## 保持玩家连接

不过，这个实现中有一件事情我们还没有解释。如果你看一下突出显示的代码，你会看到用户名被存储到了会话中。

这将允许服务器继续知道玩家的姓名，而不必在每次后续请求中都提交它。它还将允许我们允许用户在会话仍然有效的情况下继续玩游戏，而无需再次提供他/她的用户名和密码。

如果你看一下本章开头的用户交互流程图，你会看到有一个屏幕建议用户继续玩游戏。只有在服务器仍然有一个可用于他/她的有效会话时，我们才会显示它。为了检查这一点，我们将创建另一个名为`session.php`的 PHP 文件，它如下所示：

```js
<?php
   session_start();

   // MySQL connection
   include 'dbconnect.php';

    // JSON Object 
    $json = array('connected'=>'false');

   if(isset($_SESSION['name'])) {
      $query = 'SELECT * FROM players WHERE name = "'.$_SESSION['name'].'"';
      $result = mysqli_query($link, $query);
      $obj = mysqli_fetch_object($result);
      if($obj){
          $json['name'] = $_SESSION['name'];
            $json['x'] = floatval($obj->x);
            $json['y'] = floatval($obj->y);
            $json['dir'] = intval($obj->dir);
      } else {
         session_destroy();   
      }

        mysqli_free_result($result);
   }

    echo json_encode($json);

    mysqli_close($link);
?>
```

然后我们简单地检查`name`是否存在于会话中。但是，如果存在，我们还需要做一件事情；那就是从数据库中检索玩家。这将为我们提供其最后一个坐标，并再次检查用户名和密码是否确实匹配。

我们不将坐标保存在会话本身中，因为我们希望玩家能够使用许多不同的机器或浏览器连接到同一个帐户（尽管不能同时进行）。

一旦数据库执行了一个请求，我们就可以使用`mysql_result`来读取结果。这个函数需要三个参数：

1.  查询的结果，由`mysql_query`生成。

1.  我们想要读取的结果的索引。这是必要的，因为查询可能会返回多个结果（例如，如果我们在`players`表中搜索所有帐户）。

1.  我们想要读取的字段的名称。

一旦我们有了这些信息，我们就可以通过将其格式化为 JSON 文件来将其发送给客户端。

在客户端，我们将在游戏开始时调用此函数以选择要显示的屏幕（继续屏幕或登录屏幕）。这与使用`$.getJSON`调用一样通常。

```js
$.getJSON(
   "session.php",
   function(json){
      if(json.connected){
         name = json.name;
         initialPlayerPos.x   = json.x;
         initialPlayerPos.y   = json.y
         initialPlayerPos.dir = json.dir;
         $("#session-name").html(name);
         $("#session").show(0);
      } else {
         $("#login").show(0);
      }
   }
);
```

这与我们之前所做的非常相似。

## 将用户登录游戏

这几乎与我们检查现有会话的方式相同。在服务器端，我们需要发出请求来证明用户名和密码是否匹配，并获取玩家位置。

在客户端，如果密码错误，我们需要显示警告并开始游戏。

我们用于此目的的 JSON 如下所示：

```js
{ 
   "success" : true , 
   "x" : 154,
   "y" : 1043,
   "dir" :0
}; 
```

如果用户名和密码不匹配，则成功将为 false。否则，JSON 将如之前所示。我们不会向您显示服务器和客户端代码，因为它们与我们已经看到的非常相似。

# 保持玩家同步

根据我们到目前为止所看到的内容，我们可以登录游戏，但仅此而已；现在我们需要的是一种方法来让服务器了解玩家的移动并给客户端提供所有其他玩家的位置。以下图显示了客户端和服务器将如何交互：

![保持玩家同步](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_07_03.jpg)

我们将在一个 JSON 调用中执行这两个操作。我们将使用它将玩家的当前位置传递给服务器，就像之前为用户名和密码做的那样。作为回报，服务器将生成一个 JSON 文件，其中包含所有其他玩家的列表。

```js
{ 
   "players" : [
      {"name": "Alice", "x": 23, "y": 112, "dir": 0, "state": 0},
      {"name": "Bob", "x": 1004, "y": 50, "dir": 2, "state": 1}
   ]
};
```

让我们首先看一下服务器端。在那里，我们需要编写两个查询：第一个查询用于检索所有玩家的列表，第二个查询用于更新当前玩家的状态。

## 检索所有其他玩家

这仅意味着找到`players`表中除了当前玩家之外的所有条目。但是，有一件事情我们必须小心：我们只想显示当前正在玩游戏的玩家。

由于在线上可能发生很多事情，我们不能确定玩家是否能够在断开连接之前注销，因此，我们选择使用时间戳。每次玩家更新其位置时，我们将时间戳设置为当前时间。

通过比较时间戳和当前时间，我们可以知道哪些玩家不再在线了。我们随意决定，如果我们已经超过 10 分钟没有收到他/她的消息，那么玩家将被视为离线。相应的 MySQL 查询如下：

```js
$query = 'SELECT * FROM players WHERE lastupdate > TIMESTAMPADD(MINUTE, -10, NOW()) AND name <> "'.$_GET['name'].'"';
```

在这里，我们测试名称是否与当前玩家不同（`<>`在 SQL 中表示"不等于"）。

读取结果并将其打印到服务器响应的代码如下：

```js
$result = mysqli_query($link, $query);

while ($obj = mysqli_fetch_object($result)) {
    array_push($json['players'], array('name'=>$obj->name, 'x'=>floatval($obj->x), 'y'=>floatval($obj->y), 'dir'=>intval($obj->dir), 'state'=>floatval($obj->state)));
}

mysqli_free_result($result);
```

这与仅从数据库中检索当前用户时非常相似，所以您应该已经熟悉了这段代码。

## 更新当前玩家位置

要更新数据库中保存有关玩家信息的条目，我们可以使用以下查询：

```js
mysqli_query($link, 'UPDATE players SET x='.$x.', y ='.$y.', dir = '.$dir.', state = '.$state.', lastupdate = NOW() WHERE name="'.$name.'"');
```

由于我们不期望从此查询中获得任何结果，所以不需要将其存储在任何地方。

## 客户端代码

现在我们需要编写的代码将当前玩家位置发送到服务器。这并不太复杂，因为只需将参数传递给`$.getJSON`调用。但是，我们需要将玩家的方向和状态编码为整数（因为我们决定在数据库中以这种方式存储它们）。

为此，我们将扩展玩家对象，添加两个新方法：

```js
this.getState = function(){
    switch (state){
        case "idle":
            return 0;
        case "walk":
            return 1;
        case "strike":
            return 2;
        default:
            return 0;
    }
};

this.getOrientation = function(){
    switch (orientation){
        case "down":
            return 0;
        case "up":
            return 1;
        case "left":
            return 2;
        default:
            return 3; 
    }
}; 
```

然后，我们将在调用`getJSON`时简单地调用它们：

```js
$.getJSON(
   "update.php",
   {
      name: name, 
      x: gf.x(player.div), 
      y: gf.y(player.div),
      dir: player.getOrientation(),
      state: player.getState()
   },
   updateOthers
);
```

回调函数可能是这整章中最复杂的部分。遍历返回的所有玩家列表。如果创建了新玩家，我们需要将他/她添加到地图中。如果玩家移动了，我们需要更新他/她的位置，如果玩家退出了游戏，我们需要将他/她移除。

以下代码确切地做到了这一点：

```js
function(json,status){      
   // Here we need to update the position of all the other players
   var existingOthers = {};
   var players = json.players
   for (var i = 0; i < players.length; i++){
       var other = players[i];
       existingOthers["other_"+other.name] = true;
       var avatar, weapon;
       var div = $("#other_"+other.name);
       var created = false;
       if(div.size() > 0){
          avatar = $("#other_"+other.name+"_avatar");
          weapon = $("#other_"+other.name+"_weapon");
          // update
          gf.x(div, other.x);
          gf.y(div, other.y);
          div.css("z-index",other.y + 160);
       } else {
          var created = true;
          // create other players
          div = gf.addGroup($("#others"), "other_"+other.name, {
             x:      other.x,
             y:      other.y
          })
          others.push( div );
          div.css("z-index",other.y + 160);
          avatar = gf.addSprite(div, "other_"+other.name+"_avatar", {
             x:      (192-128)/2,
                y:      (192-128)/2,
                width:  128,
                height: 128
          });
          weapon = gf.addSprite(div, "other_"+other.name+"_weapon", {
                width:  192,
                height: 192
            });
          div.append("<div style='font-family: \"Press Start 2P\"; background: rgba(0,0,0,0.5); padding: 5px; color: #FFF; width: 192px; position: absolute;'>"+other.name+"</div>");
          div.data("state", {dir: other.dir, state: other.state});
       }

       // set the correct animation
       if(created || other.state !== div.data("state").state || other.dir !== div.data("state").dir){
          div.data("state", {dir: other.dir, state: other.state}); 

          gf.transform(avatar, {flipH: false});
          gf.transform(weapon, {flipH: false});
          var pAnim =  playerAnim.stand;
          var wAnim =  weaponAnim.stand;
          if(other.state === 1){
             pAnim = playerAnim.walk;
            wAnim = weaponAnim.walk;
          } else if (other.state === 2){
             pAnim = playerAnim.strike;
            wAnim = weaponAnim.strike;
          }
          if(other.dir === 0){
             gf.setAnimation(avatar, pAnim.down, true);
             gf.setAnimation(weapon, wAnim.down, true);
          } else if (other.dir === 1){
             gf.setAnimation(avatar, pAnim.up, true);
             gf.setAnimation(weapon, wAnim.up, true);
          } else {
             gf.setAnimation(avatar, pAnim.side, true);
            gf.setAnimation(weapon, wAnim.side, true);
            if(other.dir === 2){
               gf.transform(avatar, {flipH: true});
               gf.transform(weapon, {flipH: true});
            }
          }
       }

   }
   // remove gone others
   for (var i = others.length-1; i >= 0; i--){
      var other = others[i];
      if(!existingOthers[other.attr("id")]){
         other.fadeOut(2000, function(){
                $(this).remove();
            });
            others.splice(i,1);
      }
   }

   setTimeout(updateFunction,100);
}
```

第一部分是要么更新位置，要么创建其他玩家。第二部分是根据玩家的方向和状态设置正确的动画。

然后我们遍历所有玩家的列表，如果其中一些不在更新玩家列表中，我们就将它们从游戏中移除。

最后，我们设置一个函数调用`$.getJSON`的超时时间，以便在 100 毫秒后再次调用。你选择的频率将是服务器使用和游戏流畅性之间的折衷，所以你可能需要根据游戏需求微调这个值。

# 照顾怪物

现在游戏开始变得有趣了。然而，还有一件小事情缺失。如果一个玩家杀死了一个怪物，那么只有对他而言怪物才会死亡，而对其他所有玩家来说并非如此。在一些非常特殊的情况下，这可能没问题，但大多数情况下，这不是我们想要的。

解决方案是在服务器端实现处理敌人和战斗逻辑。这意味着我们需要另一个数据库表来存储所有的敌人。该表需要存储以下信息：

+   敌人的 ID，用于唯一标识它

+   敌人的类型——骷髅、食人魔等——用于定义它在玩家眼中的外观

+   敌人的 x 和 y 坐标

+   允许玩家杀死它的生命值

+   它的防御用于战斗系统

+   它的生成速率，用于确定怪物被击败后再次生成的时间

然后，我们将周期性地向客户端传输这些敌人的位置和属性。由于我们已经有一个定期轮询以获取其他玩家位置的页面，我们可以简单地将其扩展为返回敌人的状态。

这意味着 JSON 文件现在会像这样（其中突出显示了新部分）：

```js
{ 
   "players" : [
      {"name": "Alice", "x": 23, "y": 112, "dir": 0, "state": 0},
      {"name": "Bob", "x": 1004, "y": 50, "dir": 2, "state": 1}
   ],
   "enemies" : [
 {"name": "enemy1", "type" : "ogre", "x": 2014, "y": 200},
 {"name": "enemy2", "type" : "skeleton", "x": 220, "y": 560}
 ]
};
```

我们将需要另一个查询来找出数据库中仍然存活的所有敌人：

```js
SELECT * FROM enemies WHERE life <> 0
```

编写 JSON 并解析以创建或更新敌人的代码与处理其他玩家的代码完全相同，因此我们不会在此重复，但如果您想要查看完整的源代码，可以看一下。

## 实施服务器端战斗

要使用那些服务器端的敌人实现战斗，我们仍然可以使用我们在客户端拥有的代码，并将结果发送到服务器。这有一些严重的缺点，因为很容易欺骗系统并修改客户端，简单地发送敌人已被击败的信息而没有真正进行战斗。其次，它使得处理一个敌人和许多玩家之间的战斗变得非常困难。

我们将改为在服务器端实现它，如下图所示：

![实施服务器端战斗](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_07_04.jpg)

以前在客户端执行的代码如下所示：

```js
this.detectInteraction = function(npcs, enemies, console){
    if(state == "strike" && !interacted){
        // ... interaction with NPCs here ...
        for (var i = 0; i < enemies.length; i++){
            if(gf.spriteCollide(this.hitzone, enemies[i].div)){
                var enemyRoll = enemies[i].object.defend();
                var playerRoll = Math.round(Math.random() * 6) + 5;

                if(enemyRoll <= playerRoll){
                    var dead = enemies[i].object.kill(playerRoll);
                    console.html("You hit the enemy "+playerRoll+"pt");
                    if (dead) {
                        console.html("You killed the enemy!");
                        enemies[i].div.fadeOut(2000, function(){
                            $(this).remove();
                        });
                        enemies.splice(i,1);
                    }
                } else {
                    console.html("The enemy countered your attack");
                }
                interacted = true;
                return;
            }
        }
    }
```

现在我们只需进行一个 JSON 调用：

```js
this.detectInteraction = function(npcs, enemies, console){
    if(state == "strike" && !interacted){
        // ... interaction with NPCs here ...
        for (var i = 0; i < enemies.length; i++){
            if(gf.spriteCollide(this.hitzone, enemies[i])){
                $.getJSON("fight.php",
 { name : enemies[i].attr("id") },
 function(json){
 if (json.hit){
 if (json.success){
 if(json.killed){
 console.html("You killed the enemy!");
 } else {
 console.html("You hit the enemy "+json.damage+"pt");
 }
 } else {
 console.html("The enemy countered your attack");
 }
 }
 })
                interacted = true;
                return;
            }
        }
    }
};
```

在这里，您可以看到 JSON 包含两个标志，用于提供有关战斗的信息。第一个是`hit`；如果战斗确实发生了，它就是真的。这是必要的，因为有可能敌人已经死了，而客户端并不知道。然后，`success`传达了攻击的成功，如果敌人成功防御了自己，则为`false`，否则为`true`。

战斗的完整逻辑将在`fight.php`文件中在服务器端实现，但与以前在客户端发生的情况完全相同：

```js
$query = 'SELECT * FROM enemies WHERE life <> 0 AND name = "'.$name.'"';
$result = mysqli_query($link, $query);
$obj = mysqli_fetch_object($result);
if ($obj) {

    $playerRoll = rand ( 5 , 11 );
 $enemyRoll  = rand ( $obj->defense, $obj->defense + 6);

    $json['hit'] = true;

    if ($playerRoll > $enemyRoll){
        $json['success'] = true;

        if($playerRoll > $obj->life){
            $json['killed'] = true;

            // update DB
            mysqli_query($link, 'UPDATE enemies SET life = 0 WHERE name = "'.$name.'"');
        } else {
            $json['killed'] = false;
            $json['damage'] = intval($playerRoll);

            // update DB
            mysqli_query($link, 'UPDATE enemies SET life = '.($obj->life - $playerRoll).' WHERE name = "'.$name.'"');
        }
    }
}
```

突出显示的部分代表了从客户端拿出并放入服务器的代码。这就是战斗真正需要的一切。

一旦敌人死亡，您可能希望定期重新生成它。最明显的方法是使用服务器端脚本，通过`cron`命令定期执行。另外，您也可以使用我们创建的任何其他文件来重新生成敌人；例如，每次玩家登录时。

# 总结

我们在这里创建的游戏迄今为止是本书中写过的最复杂的游戏。当然，通过添加 PvP 战斗，聊天系统等等，它当然可以得到很大的增强，但本章已经涵盖了所有基础知识，使您能够实现这些！

然而，异步调用一堆文件并不是一个非常优雅的解决方案，如果您针对最近的浏览器，您可能希望看一下 WebSocket API，该 API 允许您在浏览器和服务器之间建立和维护双向通信通道。

保持与服务器的永久连接的另一种方法是使用长轮询方法。

在下一章中，我们将修改我们的平台游戏，使其与 Facebook 和 Twitter 集成，并保持高分列表！


# 第八章：让我们变得社交

自第一款视频游戏诞生以来，一种简单的技术一直被用来保持它们的趣味性——**排行榜**。排行榜是让玩家继续玩你的游戏的一种简单方法。玩家将尝试每次表现都更好，超过他们的朋友，或者比世界上其他任何玩家表现更好。

社交网络通过允许游戏将玩家的得分发布到他/她的时间线（或动态）为这个简单的想法增加了一个新的维度。这有很多优点，其中一个是它将帮助潜在的新玩家了解你的游戏。如果他们看到他们的一个朋友刚玩了你的游戏，那么他们可能也想试试！

在本章中，我们首先将展示如何使用与前一章中看到的相同技术来实现一个简单的服务器端排行榜。然后，我们将看到如何允许玩家使用他/她的 Twitter 账户登入游戏并代表他/她发推文。

最后，我们将看到如何使用 Facebook 登入游戏，将事件发布到玩家的时间线，并创建成就。

当你使用 Facebook 或 Twitter 时，重要的是要意识到你必须小心遵循他们制定的规则，并且要随时了解规则的变化，以确保你的游戏合规。已经不止一次看到之前被允许使用这些服务的应用程序或游戏随后被禁止的情况。

我们将向您展示如何使用这两个社交网络，但是几乎任何提供相同功能的服务的基本机制都是相同的。

我们会按照以下顺序涵盖这些主题：

+   创建一个简单的自托管排行榜

+   使作弊变得更困难

+   将游戏与 Twitter 集成，以允许玩家发布他/她的得分

+   将游戏与 Facebook 集成，以允许玩家赢得成就

# 创建一个简单的排行榜

显然，创建排行榜将需要某种类型的数据库来保存分数。与上一章一样，我们将使用 PHP 和 MySQL 来实现游戏的服务器端。但是，与第七章 *制作一个多人游戏*不同，一起玩的方法在现实生活中可能是可行的。请求和保存高分是一个几乎不消耗服务器资源并且不经常调用的操作；对于每个用户，我们大约每 10 秒查询一次服务器，与我们在第七章 *制作一个多人游戏*中每秒多次查询服务器的情况相比，这次不是那么频繁。

首先，我们需要一个作为得分的度量标准。在这里，我们将简单地使用玩家完成一级所需的时间，单位为秒。以下的图表展示了我们将使用的用户互动工作流程：

![创建一个简单的排行榜](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_01.jpg)

作为用户界面，我们将使用两个屏幕，我们将以与上一章节界面相同的方式实现它们——简单的`div`元素，根据需要使它们可见或不可见。

第一个屏幕只是用来宣布级别的开始，并提示用户准备好。第二个屏幕更复杂。它显示玩家的结果、前五名玩家的列表，并且如果玩家得分属于其中之一，给予他/她将姓名保存到此列表的机会。以下截图显示了这将是什么样子：

![创建一个简单的排行榜](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_02.jpg)

我们选择使用这种机制而不是在游戏开始时询问用户的姓名，然后自动保存分数，因为这模仿了旧式街机游戏的行为。

这意味着有两个服务器端的动作：

1.  检索一个级别的前五名得分列表。

1.  为给定级别保存分数。

我们将用两个文件来实现这两个动作，分别是`highscore.php`和`save.php`。

## 保存高分

我们将使用的数据库表格有三列：

+   `Level`: 这是一个保存级别索引的整数。

+   `Name`: 这是一个保存用户名的字符串。

+   `Time`: 这是一个表示用户完成级别所用秒数的整数。

保存最高分的脚本非常简单——我们将传输姓名、分数和级别到服务器。然后我们将它们用以下 SQL 查询保存到数据库中：

```js
INSERT INTO scores (level, name, time) VALUES (1, "John", 36)
```

脚本的其余部分与我们在上一章中看到的非常相似，所以我们不会在这里重复，但如果你想要，你可以查看完整的源代码。

## 检索高分

要检索高分，你只需向服务器提供级别，然后得到分数即可，但我们选择了一个稍微复杂的机制。我们将决定当前用户是否属于前五名列表，并且如果是，则在哪个位置。这将允许你稍后实现防作弊措施。

因此，你将向服务器提供级别和用户的时间，它将返回一个 JSON 文件，其中包含生成排行榜屏幕所需的所有信息。我们选择了以下格式的 JSON：

```js
{ 
  "top" :[
    {"name": "Joe", "time": 14},
    {"name": "John", "time": 15}, 
 {"time": 17},
    {"name": "Anna", "time": 19}
  ],
 "intop": true, 
 "pos": 2
} 
```

这里的想法是有一个标志来指示玩家是否在前五名列表中，`intop`。如果这个标志为真，那么另一个名为`pos`的变量也存在。此变量保存数组`top`中保存玩家时间的索引。`top`数组的所有其他条目都是排行榜中玩家的分数，从第一到第五排序。如果`intop`为假，则数组仅保存其他玩家的分数。

为了生成这个响应，我们首先使用一个 SQL 查询：

```js
SELECT * FROM scores WHERE level=1 ORDER BY time ASC LIMIT 5
```

这个查询的开始和我们直到现在为止使用的其他查询类似，但在末尾（在上面的前面代码中突出显示）有一个修改器，指定了你希望结果按升序时间排序（`ORDER BY time ASC`）并且我们只需要五个结果（`LIMIT 5`）。

解析结果并生成 JSON 不需要做太多工作。唯一需要注意的细节是如果玩家的分数达到了要求，则需要插入玩家的分数。以下是此页面的完整代码：

```js
<?php
  session_start();

  include 'dbconnect.php';

  $time = $_GET['time'];
  $level = $_GET['level'];

  if(isset($time) && isset($level)){

    // JSON Object 
    $json = array('top'=>array(), 'intop'=>false);

    $query = 'SELECT * FROM scores WHERE level='.$level.' ORDER BY time ASC LIMIT 5';
    $result = mysqli_query($link, $query);
    $i=0;

    while ($obj = mysqli_fetch_object($result)) {
 if(!$json['intop'] && $time < $obj->time){
 $json['intop'] = true;
 $json['pos'] = $i;

 array_push($json['top'], array('time'=>$time));

 $i++;
 }
 if($i < 5){
        array_push($json['top'], array('time'=>$obj->time, 'name'=>$obj->name));
        $i++;
      }
    }

 if($i < 5 && !$json['intop']){
 $json['intop'] = true;
 $json['pos'] = $i;

 array_push($json['top'], array('time'=>$time));
 }

    mysqli_free_result($result);

    echo json_encode($json);
  }

  mysqli_close($link);
?>
```

此代码的突出部分处理了玩家的得分。

## 显示高分榜

在客户端，我们将生成带有结果的屏幕，并提供一个输入字段，允许玩家将其名称提交到排行榜中，如果他/她愿意的话。让我们看看执行此操作的代码：

```js
var finishedTime = Math.round((Date.now() - levelStart) / 1000);
  $.ajax({
    dataType: "json",
    url: "highscore.php",
    data: {
      level: currentLevel,
      time: finishedTime
    },
    async: false,
    success: function (json) {
      var top = "";
 for (var i = 0; i < json.top.length; i++){
 if(json.intop && json.pos === i){
 top += "<input id='name' placeholder='_____' size='5' />"
 + "<input id='timeScore' type='hidden' value='"+json.top[i].time+"'></input>"
 + "<input id='level' type='hidden' value='"+currentLevel+"'></input>"
 + " "+minSec(json.top[i].time)
 + " <a id='saveScore' href='#'>submit</a> <br>";
 } else {
 top += "" + json.top[i].name + " " + minSec(json.top[i].time) + "<br>";
 }
      }
      $("#top_list").html(top);
    }
  }).fail(function(a,b,c){
    var toto = "toto";
  });
```

生成列表本身的代码被突出显示了。在这里，我们创建了三个输入字段——一个用于玩家输入他/她的姓名，另外两个隐藏字段用于保存关卡号和玩家分数。它们后面跟着一个链接，用于提交分数。处理此链接的代码如下：

```js
$("#levelEnd").on("click","#saveScore",function(){
    $.get("save.php",{
      name: $("#name").val(),
      time: $("#timeScore").val(),
      level: $("#level").val()
    }, function(){
      $("#saveScore").fadeOut(500);
    });
    return false;
  });
```

在这里，我们简单地检索输入字段的值，然后将它们提交到服务器。作为对玩家的小反馈，一旦完成，我们就删除提交按钮。

# 加大作弊难度

避免作弊并没有通用的灵丹妙药。对于使用 JavaScript 编写的游戏来说尤其如此，因为它们的源代码非常容易访问。当然，你可以混淆你的代码，但这只会延缓真正有动力破解你的代码的人。然而，还有一些其他技术可以使在你的游戏中作弊变得更加困难或者效率更低。

## 服务器端验证

预防作弊最安全的方法是在服务器端进行操作。如果你还记得，在第七章中，我们在我们的 MMORPG 中的战斗机制中确实是这样做的，*Making a Multiplayer Game*。将相同的范式应用于平台游戏实际上意味着将每次按键都传输到服务器，并让服务器决定玩家的最终位置。

在大多数情况下，这不是一个现实的解决方案。但你仍然可以使用服务器端逻辑来验证玩家提交的分数。你可以在关卡中分布一系列不可见的检查点，在这些检查点上进行服务器的响应。如果用户提交了一个分数，而没有通过每一个检查点，那么肯定是有问题的。你还可以记录一系列指标，比如玩家死亡或跳跃的次数。

问题在于你必须真正为你的游戏定制验证方式；没有通用的方法。然而，非常重要的一点是，你的反作弊措施不应该将一个诚实的玩家标记为作弊者，因为那会引起很多沮丧。你还需要考虑要在这个领域投入多少精力，因为你在这方面花费的时间越多，你在游戏的其他领域花费的时间就越少。

对于您的游戏，我们将实现一些简单的东西。我们知道玩家的移动速度有多快，我们知道级别结束有多远，所以我们可以计算出玩家通过级别所需的最短时间。我们将把玩家的分数与此进行比较，如果不小，则进行验证。

要做到这一点，我们只需在`highscore.php`中添加这些行：

```js
// player walk may 7px in 30ms -> 233.1
$minTime = array(
 1 => 15, // 3500 / 233.1 
 2 => 15, // 3500 / 233.1 
 3 => 42, // 9800 / 233.1
 4 => 23 // 5460 / 233.1
);
$timeValid = !($minTime[intval($level)] < intval($time));
//...
while ($obj = mysqli_fetch_object($result)) {
  if(!$json['intop'] && $time < $obj->time && $timeValid){
    // ...
  }
```

如果玩家分数被检测为`impossible`，它仍将被显示，但玩家不会被提示输入他/她的姓名。

## 使您的变量不太易读

您可以做的一件事是通过在浏览器的检查器中打开并更改某个值，使作弊游戏变得更加困难，因为我们在发送回服务器之前使用隐藏的输入字段来存储值，以保存最高分。这在纯语义上是有意义的，并使我们的服务器端实现得到了休息，但非常容易被黑客入侵。以下截图显示了用户如果在 Chrome 的页面检查器中打开页面将会看到什么：

![使您的变量不太易读](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_03.jpg)

一个简单的经验法则是避免在 DOM 中存储任何重要信息，因为它对任何用户都是可访问的，即使是那些没有太多编程知识的用户也是如此。在我们的情况下，我们将从对`save.php`的调用中删除这些信息，并改用会话来存储这些值。在`highscore.php`中，我们可以简单地添加以下代码：

```js
if(!$json['intop'] && $time < $obj->time && $timeValid){
  $json['intop'] = true;
  $json['pos'] = $i;

  array_push($json['top'], array('time'=>$time));

 $_SESSION['level'] = $level;
 $_SESSION['time'] = $time;

  $i++;
}
```

`save.php`文件只需在会话中查找级别和时间：

```js
$name = $_GET['name'];
$time = $_SESSION['time'];
$level = $_SESSION['level'];
```

这个简单的改变已经使得游戏更难以作弊。

## 对代码进行混淆

对代码进行混淆是一个非常简单的步骤，但会对您有很大帮助。一旦您的代码被混淆，它在检查器中将几乎无法阅读。以下示例是要求排行榜的一段代码：

```js
if (status == "finished") {
  gameState = "menu";
  $("#level_nb_2").html(currentLevel);
  $("#level_nb_1").html(currentLevel + 1);

  var finishedTime = Math.round((Date.now() - levelStart) / 1000);
  $.ajax({
    dataType: "json",
    url: "highscore.php",
    data: {
      level: currentLevel,
      time: finishedTime
    },
    async: false,
    success: function (json) {
      var top = "";
      for (var i = 0; i < json.top.length; i++){
        if(json.intop && json.pos === i){
          top += "<input id='name' placeholder='_____' size='5' />"
            + "<input id='timeScore' type='hidden' value='"+json.top[i].time+"'></input>"
            + "<input id='level' type='hidden' value='"+currentLevel+"'></input>"
            + " "+minSec(json.top[i].time)
            + " <a id='saveScore' href='#'>submit</a> <br>";
        } else {
          top += "" + json.top[i].name + " " + minSec(json.top[i].time) + "<br>";
        }
      }
      $("#top_list").html(top);
    }
  }).fail(function(a,b,c){
    var toto = "toto";
  });

  $("#time").html(minSec(finishedTime));

  $("#levelEnd").fadeIn(2000, function(){
    $("#backgroundFront").css("background-position","0px 0px");
    $("#backgroundBack").css("background-position","0px 0px");
    gf.x(group, 0);

    tilemap = loadNextLevel(group);
    gf.x(player.div, 0);
    gf.y(player.div, 0);
    gf.setAnimation(player.div, playerAnim.jump);
  });
  status = "stand";
}
```

通过 UglifyJS 进行混淆后的相同代码看起来类似于以下内容：

```js
if("finished"==status){gameState="menu",$("#level_nb_2").html(currentLevel),$("#level_nb_1").html(currentLevel+1);var finishedTime=Math.round((Date.now()-levelStart)/1e3);$.ajax({dataType:"json",url:"highscore.php",data:{level:currentLevel,time:finishedTime},async:!1,success:function(a){for(var b="",c=0;a.top.length>c;c++)b+=a.intop&&a.pos===c?"<input id='name' placeholder='_____' size='5' /><input id='timeScore' type='hidden' value='"+a.top[c].time+"'></input>"+"<input id='level' type='hidden' value='"+currentLevel+"'></input>"+" "+minSec(a.top[c].time)+" <a id='saveScore' href='#'>submit</a> <br>":""+a.top[c].name+" "+minSec(a.top[c].time)+"<br>";$("#top_list").html(b)}}).fail(function(){}),$("#time").html(minSec(finishedTime)),$("#levelEnd").fadeIn(2e3,function(){$("#backgroundFront").css("background-position","0px 0px"),$("#backgroundBack").css("background-position","0px 0px"),gf.x(group,0),tilemap=loadNextLevel(group),gf.x(player.div,0),gf.y(player.div,0),gf.setAnimation(player.div,playerAnim.jump)}),status="stand"}
```

这已经更难调试了，同时，代码量更小！

## 使您的网络协议不太易读

一旦客户端代码修复好了，仍然有一个地方作弊者可以访问游戏变量——网络流量。让我们看看当玩家完成级别时，嗅探应用程序可以看到什么：

![使您的网络协议不太易读](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_04.jpg)

这是一个问题，因为即使不需要黑客客户端代码，玩家也可以简单地伪造一个带有正确信息的数据包来作弊。以下是您可以做的三件简单事情，使作弊者更难理解您的网络流量：

1.  为变量赋予随机名称，以便作弊者仅凭看它们就无法找出它们保存的值。

1.  对变量的内容进行编码。这对于此情况非常有用，因为在这里用户通常知道自己分数的值。他/她只需查找保存它的变量，就可以找出需要修改的内容。

1.  添加大量随机变量，以使很难知道哪些真正被使用了。

像以前一样，这只会让决心的玩家稍微难以作弊，但与以下各节中的所有其他技术结合起来，它可能会阻止大多数人。让我们实施这些技术。

### 编码数值

让我们首先开始编码数值。这可以用许多方式来完成，有些比其他更安全。在这里，我们的目标只是防止作弊者从值列表中搜索他/她的分数以确定哪个持有它。所以，我们不需要任何复杂的编码。我们将简单地使用左移（客户端上的`<<`）然后右移（服务器上的`>>`）。

这里是客户端代码：

```js
$.ajax({
  dataType: "json",
  url: "highscore.php",
  data: {
    level: currentLevel,
 time: finishedTime << 1
  },
  async: false,
  success: function (json) {
    // ...
  }
});
```

服务器端对应如下：

```js
$time = intval($_GET['time']) >> 1;
```

为了进一步迷惑用户，我们将以清晰的方式传输数值到许多其他变量中，这些变量在服务器端是无法读取的。

### 随机命名变量

这里没有太多需要解释的内容；只需替换变量的名称！如果你真的很偏执，那么每次调用服务器时都可以更改变量，但我们不会这样做。以下是客户端代码：

```js
$.ajax({
  dataType: "json",
  url: "highscore.php",
  data: {
 Nmyzsf: currentLevel,
 WfBCLQ: finishedTime << 1
  },
  async: false,
  success: function (json) {
    // ...
  }
});
```

服务器端代码如下：

```js
$time = intval($_GET['WfBCLQ']) >> 1;
$level = $_GET['Nmyzsf'];
```

### 添加随机变量

现在变量的名称不再传达它们的内容，非常重要的是你创建更多变量，否则很容易只是尝试每一个来找出哪一个包含分数。以下是您在客户端可能做的示例：

```js
$.ajax({
  dataType: "json",
  url: "highscore.php",
  data: {
 sXZZUj: Math.round(200*Math.random()),
 enHf8F: Math.round(200*Math.random()),
 eZnqBG: currentLevel,
 avFanB: Math.round(200*Math.random()),
 zkpCfb: currentLevel,
 PCXFTR: Math.round(200*Math.random()),
    Nmyzsf: currentLevel,
 FYGswh: Math.round(200*Math.random()),
 C3kaTz: finishedTime << 1,
 gU7buf: finishedTime,
 ykN65g: Math.round(200*Math.random()),
 Q5jUZm: Math.round(200*Math.random()),
 bb5d7V: Math.round(200*Math.random()),
 WTsrdm: finishedTime << 1,
 bCW5Dg: currentLevel,
 AFM8MN: Math.round(200*Math.random()),
 FUHt6K: Math.round(200*Math.random()),
    WfBCLQ: finishedTime << 1,
 d8mzVn: Math.round(200*Math.random()),
 bHxNpb: Math.round(200*Math.random()),
 MWcmCz: finishedTime,
 ZAat42: Math.round(200*Math.random())
  },
  async: false,
  success: function (json) {
    // ...
  }
});
```

服务器不需要做任何更改，因为这些新变量只是被忽略的。你可能想做一些事情，比如重复值，并在不会被使用的变量上使用玩家分数。

在做这些事情的同时，您必须非常小心地注释代码，以便记住哪些变量是正确的！

# 与 Twitter 集成

Twitter 是与其他人分享简单信息的绝佳方式。您可能希望以两种方式使用它：

+   允许玩家登录，从而提供一个唯一的用户名

+   允许玩家发布他/她在游戏中的最高分或进度

现在你将看到两种将你的游戏与之集成的可能性。

## Twitter 入门指南

有一种非常简单的方法可以使用 Twitter，甚至不需要您使用任何类型的 API。如果用户已经登录到 Twitter，您可以提示他/她通过打开一个 URL 提交一个预先写好的推文。这个 URL 的格式如下：

```js
http://twitter.com/home?status=Pre written status here!

```

此地址的突出部分是您为玩家编写的状态。我们在游戏中可以做的是在排行榜屏幕上的**提交**按钮旁提供一个`tweet` `this`链接：

```js
$.ajax({
  dataType: "json",
  url: "highscore.php",
  data: {
    // ...
  },
  async: false,
  success: function (json) {
    var top = "";
    for (var i = 0; i < json.top.length; i++){
      if(json.intop && json.pos === i){
        top += "<input id='name' placeholder='_____' size='5' />"
          + " "+minSec(json.top[i].time)
          + " <a id='saveScore' href='#'>submit</a>"
          + " <a id='tweetScore' target='_blank' href='http://twitter.com/home?status="+escape("I've just finished level "+currentLevel+" in YAP in "+minSec(json.top[i].time)+"!")+"'>tweet</a> <br>";
      } else {
        top += "" + json.top[i].name + " " + minSec(json.top[i].time) + "<br>";
      }
    }
    $("#top_list").html(top);
  }
});
```

突出显示的部分就是魔法发生的地方。您会注意到我们使用了 JavaScript 的`escape`函数来确保我们提供的字符串格式化为 URL。

这种方法非常容易实现，但有一些限制：

+   如果用户尚未登录，则必须先登录后才能发布推文。

+   您无法访问用户的 Twitter 账号来用于本地排行榜。这意味着如果玩家想要发送推文并节省时间，那么名字也必须在这里输入。

+   对于每条推文，都会打开一个新窗口，玩家必须确认。

如果您想要允许用户登录并自动发布推文，而无需每次都打开新窗口，则必须使用 Twitter 的 API。

## 获得完整的 Twitter API 访问权限

与 Twitter 集成的更完整的解决方案是要求用户允许将其账户连接到游戏。此基本机制使用 **OAuth**，这是一种得到很多公司支持的开放认证标准，如 Twitter、Google 和 Facebook。

要让玩家选择是否使用 Twitter 登录，我们将稍微更改启动屏幕：

![获得完整的 Twitter API 访问权限](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_05.jpg)

如果玩家点击 **开始游戏**，那么他/她将开始游戏。如果他/她点击 **用 Twitter 登录**，那么他/她将被提示授权游戏与 Twitter，并然后返回游戏的启动屏幕。

### 在 Twitter 注册您的游戏

在做任何其他事情之前，您必须先在 Twitter 上注册您的游戏。要做到这一点，首先您需要登录 Twitter 开发者网站 ([`dev.twitter.com`](https://dev.twitter.com))。然后，您可以点击 **我的应用程序**：

![在 Twitter 注册您的游戏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_06.jpg)

在这里，您可以点击 **创建新应用**，填写所有必填字段，并同意 **规则** 条款和条件。一旦完成，您将收到一个屏幕提示，向您展示您新创建的应用程序的所有属性：

![在 Twitter 注册您的游戏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_07.jpg)

请注意此屏幕截图中的两个圈起来的代码区域；您稍后会需要它们。在这里还有一件您需要配置的事情。转到 **设置** 选项卡，滚动到 **应用程序类型**。这里，默认选择 **只读**。如果您想要能够代表用户发布推文，则需要将其更改为 **读写**：

![在 Twitter 注册您的游戏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_08.jpg)

就这样；你的游戏现在应该在 Twitter 方面正确配置了。

### 服务器端辅助库

您可以直接在 PHP 中实现与 Twitter API 的所有交互，但这将是繁琐的；幸运的是，存在许多库可以帮助您。PHP 的一个叫做 **twitteroauth**（[`github.com/abraham/twitteroauth`](http://github.com/abraham/twitteroauth)）。其他语言有其他库，所以不要犹豫，查看 Twitter 的开发者文档以了解更多信息。

twitteroauth 的非常好的一点是，你几乎可以将其安装在支持 PHP 的几乎任何类型的托管上。你只需要将库文件复制到与游戏文件相同的目录中即可。在我们的例子中，我们将它们复制到一个名为`twitter`的子目录中。

现在，您需要配置该库。为此，请从`twitteroauth`文件夹中打开`config.php`：

```js
define('CONSUMER_KEY', '(1)');
define('CONSUMER_SECRET', '(2)');
define('OAUTH_CALLBACK', '(3)');
```

在这个文件中，在`(1)`和`(2)`处，你必须写下你之前在 Twitter 开发者网站上的应用页面中记下的两个值。然后，在`(3)`处，你必须写下 twitteroauth 的`callback.php`文件的 URL。

最后一步是编辑`callback.php`，并用你游戏的索引文件的地址替换以下行：

```js
header('Location: ./index.php');
```

### 身份验证

这是用于使用 Twitter 对您的游戏进行身份验证和授权的工作流程：

![身份验证](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_09.jpg)

这并不像看起来的那么复杂，而这个工作流程的一大部分已经由 twitteroauth 实现了。我们现在将创建一个带有**Twitter**按钮的登录页面。我们将使用一个简单的链接，指向 twitteroauth 的`redirect.php`文件。当玩家第一次点击它时，他/她将被重定向到 Twitter 网站上的一个页面，要求他/她授权该游戏：

![身份验证](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_10.jpg)

然后，一旦玩家这样做，他/她将被重定向回您在`callback.php`文件中指定的 URL。如果玩家已经这样做过一次，他/她将能够直接登录。

从现在开始有用的是，在我们的 JavaScript 代码中知道玩家是否已经连接或没有。为此，让我们将我们的游戏 HTML 文件转换为 PHP 文件，并在其开头添加以下代码：

```js
<?php 
session_start();

require_once('twitter/twitteroauth/twitteroauth.php');
require_once('twitter/config.php');

/* Get user access tokens out of the session. */
$access_token = $_SESSION['access_token'];
$connection = new TwitterOAuth(CONSUMER_KEY, CONSUMER_SECRET, $access_token['oauth_token'], $access_token['oauth_token_secret']);
$user = $connection->get('account/verify_credentials');

?>
```

此代码启用了会话跟踪，包括`twitteroauth`库的一些文件，然后检查会话中是否存储了访问令牌。如果玩家使用 Twitter 登录，则会出现这种情况。

然后，服务器连接到 Twitter 以检索用户对象。这一切都很好，但 JavaScript 代码仍然对所有这些一无所知。我们需要的是创建一个自定义脚本，其中包含我们想要传输给客户端 JavaScript 的值：

```js
<script type="text/javascript">
<?php if($_SESSION['status'] == 'verified'){ ?>
  var twitter = true;
  var twitterName = "<?php print $user->screen_name; ?>";
<?php } else { ?>
  var twitter = false;  
<?php } ?>
</script>
```

现在，如果玩家使用 Twitter 登录，我们将全局变量`twitter`设置为`true`，并且全局变量`twitterName`保存玩家的屏幕名称。

你可能想做的最后一件事是向用户提供他/她已成功使用 Twitter 登录的反馈，并为他/她提供注销的可能性。为此，如果玩家已经登录，则我们将轻微更改开始屏幕：

```js
<div id="startScreen" class="screen">
 <?php if($_SESSION['status'] != 'verified'){ ?>
 <a class="button tweetLink" href="./twitter/redirect.php">Login with Twitter</a> 
 <?php } else { ?>
 <a class="button tweetLink" href="./twitter/clearsessions.php">Logout from Twitter</a>
 <?php }?>
  <a id="startButton"class="button" href="#">Start game</a>
</div>
```

通过这些相对较小的更改，您已经通过 Twitter 实现了身份验证。

### 在 Twitter 上发布高分

现在用户已连接到 Twitter，你可以让他/她以更无缝的方式发布他/她的时间。为此，我们将创建一个名为 `twitterPost.php` 的新的服务器端脚本。这个文件将使用 Twitter 的 `statuses/update` API。

让我们看看完整的脚本：

```js
<?php
session_start();
require_once('twitter/twitteroauth/twitteroauth.php');
require_once('twitter/config.php');

$time = $_SESSION['time'];
$level = $_SESSION['level'];
if(isset($time) && isset($level)){
  /* Get user access tokens out of the session. */
  $access_token = $_SESSION['access_token'];
  $connection = new TwitterOAuth(CONSUMER_KEY, CONSUMER_SECRET, $access_token['oauth_token'], $access_token['oauth_token_secret']);

 $parameters = array('status' => 'I\'ve just finished level '.$level.' for Yet Another Platformer in '.$time.' seconds!');
 $status = $connection->post('statuses/update', $parameters); 
}
?> 
```

你可能会认出我们在游戏页面开头添加的大部分代码（只有高亮部分是新的）。最后两行代码创建并发送到 Twitter 你想要发布的状态。这很简单直接，但我们可以做的更多——因为玩家已登录，你知道他/她的用户名，你可以用来制作排行榜。

在客户端代码中，我们将生成一个稍微不同版本的排行榜，如下所示：

```js
$.ajax({
  dataType: "json",
  url: "highscore.php",
  data: {
    // ...
  },
  async: false,
  success: function (json) {
    var top = "";
    for (var i = 0; i < json.top.length; i++){
      if(json.intop && json.pos === i){
 if (twitter){
 top += "<input id='name' type='hidden' val='"+twitterName+"'/>"
 + twitterName + " " + minSec(json.top[i].time)
 + " <a id='saveScore' href='#'>submit</a>"
 + " <a id='tweetScore' href='#'>tweet</a> <br>";
 } else {
          top += "<input id='name' placeholder='_____' size='5' />"
          + " "+minSec(json.top[i].time)
          + " <a id='saveScore' href='#'>submit</a>"
          + " <a target='_blank' href='http://twitter.com/home?status="+escape("I've just finished level "+currentLevel+" in YAP in "+minSec(json.top[i].time)+"!")+"'>tweet</a> <br>";
        }
      } else {
        top += "" + json.top[i].name + " " + minSec(json.top[i].time) + "<br>";
      }
    }
    $("#top_list").html(top);
  }
});
```

在这里，我们将包含玩家名称的输入字段隐藏起来，并填入用户的用户名。然后，在排行榜中写入用户名。这个好处是，服务器端代码完全不需要改变。

这就是我们在 Twitter 中实现的所有内容了，但我鼓励你去看一看完整的 Twitter API，并且发挥创造力！

# 与 Facebook 集成

在很多方面，与 Facebook 的集成类似于与 Twitter 的集成。然而，Facebook 提供了更多的游戏定向。在我们的情况下，我们将为已登录用户实施成就。我们将使用 Facebook 的 PHP SDK，但也支持其他语言。

至于 Twitter，我们需要首先在 Facebook 中注册我们的应用程序。要做到这一点，登录到 Facebook 的开发者网站（[`developers.facebook.com/`](https://developers.facebook.com/)）并点击页眉中的 **Apps**：

![与 Facebook 集成](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_11.jpg)

然后，点击 **Create New Apps** 并填写所需的信息。然后你将看到新创建的应用程序页面。在这里，你需要记下下面截图中显示的两个值（就像我们为 Twitter 所做的那样）：

![与 Facebook 集成](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_12.jpg)

如果你看一下上述截图中的红色箭头，你会注意到你可以选择你的应用和 Facebook 将如何交互。要完全访问 Facebook 的 Open Graph API，其中包括发布成就在内，你需要选择 **App on Facebook**。

这将允许你的游戏加载到 Facebook 的 iframe 中。不过，你需要在你的域名上安装有效的 HTTPS 证书。但是，如果你只希望你的游戏从你自己的服务器加载，那么你就不需要任何（你仍然需要在相应字段中输入一个地址，并且你可以简单地在你的不安全地址前加上 `https` 来使其有效）。

有一个最后需要做的步骤，即使你的 Facebook 应用程序能够提供成就——将它注册为游戏。要做到这点，只需在左侧点击 **App Details**。然后，在 **App Info** | **Category** 下选择 **Games**，如下面的截图所示：

![与 Facebook 集成](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_13.jpg)

## 与 Facebook 进行身份验证

Facebook 的基本身份验证机制与 Twitter 的非常相似。然而，关于访问的一个小差别在于，在 Twitter 中，您必须定义您的应用程序在开发者网站上需要读取和写入访问权限，而在 Facebook 中，您要求用户的访问权限的细粒度要高得多，只有在登录阶段才能指定这些。

让我们来看看身份验证所需的代码。就像对于 Twitter 一样，我们将首先编写在游戏文件的开头尝试获取用户的指令：

```js
<?php 
session_start();

// Twitter ... 

// Facebook
require 'facebook/facebook.php';

$app_id = '(1)';
$app_secret = '(2)';
$app_namespace = 'yap_bookdemo';
$app_url = 'http://yetanotherplatformer.com/';
$scope = 'publish_actions';

$facebook = new Facebook(array(
  'appId' => $app_id,
  'secret' => $app_secret,
));

// Get the current user
$facebookUser = $facebook->getUser();

?>
```

突出显示的行定义了我们希望我们的游戏能够在玩家的时间轴上发布条目。值`(1)`和`(2)`是你在应用程序配置页面中记录的值。

如果`$facebookUser`为空，这意味着用户已经登录，否则我们将不得不显示一个登录按钮。为此，我们将编写一个与我们为 Twitter 编写的代码非常相似的代码：

```js
<div id="startScreen" class="screen">
  ...
 <?php if(!$facebookUser){ 
 $loginUrl = $facebook->getLoginUrl(array(
 'scope' => $scope,
 'redirect_uri' => $app_url
 ));
 ?>
 <a class="button tweetLink" href="<?php print $loginUrl; ?>">Login with Facebook</a>
 <?php } else { 
 $logoutUrl = $facebook->getLogoutUrl(array(
 'next' => $app_url
 )); 
  ?>
    <a class="button tweetLink" href="<?php print $logoutUrl; ?>">Logout from Facebook</a>
  <?php } ?>
  <a id="startButton"class="button" href="#">Start game</a>
</div>
```

在这里，您可以看到 Facebook 的 PHP SDK 提供了一个方便的方法来生成用户登录或注销的 URL。

现在，我们将添加一小段代码来指示 JavaScript 代码用户是否已经登录到 Facebook。再一次，这里的代码与我们用于 Twitter 的代码非常相似：

```js
<script type="text/javascript">
   // ...
  <?php if($facebookUser){ ?>
    var facebook = true;
    var facebookId = "<?php print $facebookUser; ?>";
  <?php } else { ?>
    var facebook = false;  
  <?php } ?>
</script>
```

## 创建成就

现在我们将为我们的游戏创建一个成就。为此，您需要在服务器上有两个文件：

+   一个具有一系列`meta`标签的 HTML 文件

+   一幅图像文件，将在玩家的时间轴上代表成就

HTML 文件不仅作为成就的配置文件，还将链接到在您玩家的时间轴上发布的成就。为了使 Facebook 认可成就有效，您需要在头部定义以下七个`meta`标签：

+   `og:type`包含值`game.achievement`。它区分了成就与其他类型的 OpenGraph 实体。

+   `og:title`是成就的非常简短的描述。

+   `og:url`是当前文件的网址。

+   `og:description`是成就的较长描述。

+   `og:image`是前面提到的图像。它可以是 PNG、JPEG 或 GIF 格式，并且至少有 50 x 50 像素的大小。最大的长宽比是 3:1。

+   `game:points`是与此成就相关联的积分数。总共，您的游戏不能给出超过 1000 点，最小允许的数字是 1。具有更高点值的成就将更有可能显示在玩家的好友的新闻动态中。

+   `fb:app_id`是您的应用程序的 ID。

HTML 文件的正文可以是一个很好的页面，解释这个成就到底是什么，或者任何你真正想要的东西。一个完整的成就页面的非常简单的例子如下：

```js
<html> 
  <head>
    <meta property="og:type" content="game.achievement" />
    <meta property="og:title" content="Finished level 1" />
    <meta property="og:url" content="http://8bitentropy.com/yap/ach1.html" />
    <meta property="og:description" content="You just finished the first level!" />
    <meta property="og:image" content="http://8bitentropy.com/yap/ach1.png" />
    <meta property="game:points" content="50" />
    <meta property="fb:app_id" content="(1)" />
  </head>
  <body>
    <h1>Well done, you finished level 1!</h1>
  </body>
</html>
```

生成的成就将会在玩家的时间轴上显示如下截图：

![创建成就](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_08_14.jpg)

但仅仅写这份文档还不足以完全配置您的成就。您需要将其提交给 Facebook。为了做到这一点，您必须在正确的 URL 上使用正确的参数进行`POST`请求。这个请求还应该关联一个应用程序令牌。

应用程序令牌是 Facebook 确保通信对象真的是您的游戏而不是其他应用程序的一种方式。最简单的方法是编写一个 PHP 页面来提交您的成就。下面是完整代码：

```js
<?php

require 'facebook/facebook.php';

$app_id = '(1)';
$app_secret = '(2)';
$app_namespace = 'yap_bookdemo';
$app_url = 'http://yetanotherplatformer.com/';
$scope = 'publish_actions';

$facebook = new Facebook(array(
  'appId' => $app_id,
  'secret' => $app_secret,
));

$app_access_token = get_app_access_token($app_id, $app_secret);
$facebook->setAccessToken($app_access_token);

$response = $facebook->api('/(1)/achievements', 'post', array(
 'achievement' => 'http://yetanotherplatformer.com//ach1.html',
));

print($response);

// Helper function to get an APP ACCESS TOKEN
function get_app_access_token($app_id, $app_secret) {
  $token_url = 'https://graph.facebook.com/oauth/access_token?'
   . 'client_id=' . $app_id
   . '&client_secret=' . $app_secret
   . '&grant_type=client_credentials';

  $token_response =file_get_contents($token_url);
  $params = null;
  parse_str($token_response, $params);
  return $params['access_token'];
}

?>
```

这段代码非常冗长，但您将会认出其中大部分内容。重要部分已经标出——首先，我们检索应用程序令牌，然后将其与将来的请求关联，最后使用 SDK 进行`POST`请求。

这个`POST`请求的地址格式如下："应用程序 ID" / "achievements"。传输的参数就是成就文件的 URL。

由于此处生成的错误消息（如果出现问题）可能相当难以理解，您可能首先希望使用 Facebook 提供的调试工具对成就文件进行验证，网址为[`developers.facebook.com/tools/debug/`](https://developers.facebook.com/tools/debug/)。

## 发布成就

现在 Facebook 已经注册了成就，我们可以将其授予我们的玩家。执行这个命令也是一个`POST`请求，必须关联一个应用程序令牌。为了简单起见，我们将创建一个简单的 PHP 页面，在被调用时授予成就。在现实情况下，这绝不是最佳方案，在那种情况下，您希望避免让用户自行调用这个文件。您可以在`highscore.php`文件中授予成就。

这是该文件的完整代码；它与我们用来注册成就的文件非常相似，不同之处已经标出：

```js
<?php 
session_start();

// Facebook
require 'facebook/facebook.php';

$app_id = '(1)';
$app_secret = '(2)';
$app_namespace = 'yap_bookdemo';
$app_url = 'http://yetanotherplatformer.com/';
$scope = 'publish_actions';

$facebook = new Facebook(array(
  'appId' => $app_id,
  'secret' => $app_secret,
));

// Get the current user
$facebookUser = $facebook->getUser();

$app_access_token = get_app_access_token($app_id, $app_secret);
$facebook->setAccessToken($app_access_token);

$response = $facebook->api('/'.$facebookUser.'/achievements', 'post', array(
 'achievement' => 'http://yetanotherplatformer.com/ach1.html'
));

print($response);

// Helper function to get an APP ACCESS TOKEN
function get_app_access_token($app_id, $app_secret) {
  ...
}

?>
```

这次，我们创建一个`POST`请求到一个 URL，格式为："用户 ID" / "achievements"。现在，我们只需在用户完成第一关时从游戏中异步调用此文件：

```js
if (status == "finished") {
  ...
 if(facebook && currentLevel === 1){
 $.get("ac h1.php");
 }
  ...
```

# 概要

在这一章中，我们学到了很多，尽管我们只是探索了新工具所可能具有的社交互动的表面。Facebook 和 Twitter 的 API 非常庞大且不断变化。如果您希望以最佳方式使用它们，我真的建议阅读它们的完整文档。

但是，当使用第三方服务时，尤其是免费的那些，您必须意识到您变得依赖它们了。它们可以随时更改任何内容，而不会通知您太多。它们可以决定不再让您的游戏使用它们的服务。始终记住这一点，如果可能的话，确保您在这些情况下有一个退出策略！

在下一章中，我们将探讨另一个热门话题——使你的游戏适用于移动设备！为此，我们将把我们的平台游戏扩展到可以在现代智能手机和平板电脑上运行。
