# ImpactJS HTML5 游戏开发（二）

> 原文：[`zh.annas-archive.org/md5/441DA316F62E4350E9115A286AB618B0`](https://zh.annas-archive.org/md5/441DA316F62E4350E9115A286AB618B0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：让我们建立一个侧向滚动游戏

在本章中，我们将使用 ImpactJS 和 Box2D 构建一个非常基本的侧向滚动游戏。Box2D 是一个开源的 C++物理引擎。使用它，重力和摩擦力会被模拟，就像你在愤怒的小鸟游戏中看到的那样。虽然不是完全集成，但经过足够的努力，Box2D 可以在 ImpactJS 游戏中使用。就像上一章一样，游戏将从头开始构建。主要区别在于使用物理引擎和侧向滚动游戏设置。

在本章中，我们将涵盖：

+   侧向滚动游戏

+   使用 Box2D 与 ImpactJS

+   使用 ImpactJS Weltmeister 构建一个侧向滚动关卡

+   引入一个可玩的角色

+   在侧向滚动游戏中添加一些敌人

+   为玩家配备子弹和炸弹

+   使用人工智能使敌人更聪明

+   创建玩家可以拾取的物品

+   保持得分并在每次敌人死亡时添加分数

+   连接两个不同的侧向滚动关卡

+   以强大的敌人结束游戏

# 侧向滚动游戏设置

侧向滚动视频游戏是一种从侧面角度观看的游戏，玩家通常在玩过程中从左到右移动。屏幕基本上是从一侧滚动到另一侧，无论是从左到右还是其他方向，因此得名侧向滚动。著名的侧向滚动游戏有 2D 马里奥、索尼克、大金刚、旧版洛克人、超级任天堂和 Gameboy 版的银河战士游戏，以及古老但成功的双战龙。

这种类型的大多数游戏都有一个长的关卡，英雄需要通过战斗或避开怪物和死亡陷阱找到自己的路。到达关卡的结尾后，通常除了重新开始该关卡之外，没有其他回头的办法。《银河战士》在这方面有些奇怪，因为它是最早的侧向滚动游戏之一，拥有一个你可以像在标准角色扮演游戏（RPG）中一样探索的巨大世界。《银河战士》为侧向滚动游戏的新思维方式奠定了基础；你需要在虚拟的数英里长的洞穴中找到自己的路，偶尔会发现自己回到起点。《梦幻城堡》是另一个例子，这是一个使用中世纪背景的侧向滚动冒险游戏。

![侧向滚动游戏设置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_1.jpg)

既然我们已经了解了侧向滚动游戏是什么，让我们开始用 ImpactJS 构建一个。

## 为 Box2D 准备游戏

在我们正式开始之前，我们需要确保所有文件都正确放置：

1.  从我们在第一章中准备的原始 ImpactJS 可下载文件夹中复制一份，*启动你的第一个 Impact 游戏*。或者，你也可以再次下载一个新的，并将其放在 XAMPP 服务器的`htdocs`目录中。给你的文件夹起一个名字；让我们完全原创，叫它`chapter4`。其他名字也可以。

1.  从 ImpactJS 网站下载物理演示，并转到其`plugins`文件夹。在这里，你应该找到`Box2D`插件。创建你自己的`plugins`文件夹，并将`Box2D`扩展放在那里。

1.  通过在浏览器中访问`localhost/chapter4`来测试一切是否正常。**它正常工作！**消息应该再次等待着你。

1.  此外，我们还需要更改一些 Box2D 核心文件。Box2D 不是 ImpactJS 的产品，而是在开发 JavaScript 等效版本之前为基于 C++的游戏而发明的。然后，Dominic Szablewski（ImpactJS 的创造者）将这个 JavaScript 版本与 ImpactJS 集成。然而，存在一些缺陷，其中一个是错误的碰撞检测。因此，我们需要用一个修正了这个问题的适应文件来替换其中一个原始文件。从可下载的`chapter4`文件夹中获取`game.js`和`collision.js`脚本，并将它们放在本地的`Box2D`文件夹中。`collision.js`脚本得益于提供该脚本的 Abraham Walters。

1.  将`chapter4`文件夹的媒体文件复制到本地的`media`文件夹中。

1.  我们需要对主脚本进行调整。我们的游戏将不再是标准 Impact 游戏类的扩展。

```js
MyGame = ig.Game.extend({ 
```

1.  相反，它将是修改后的 Box2D 版本的扩展。因此，请确保更改以下代码片段：

```js
MyGame = ig.Box2DGame.extend({
```

1.  我们需要在`main.js`脚本的开头包含 Box2D 的`game`文件才能使用这个扩展。

```js
.requires(
  'impact.game',
  'impact.font',
  'plugins.box2d.game'
)
```

1.  最后，为了测试一切是否正常，我们需要加载一个带有碰撞层的关卡。这是因为 Box2D 需要碰撞层来创建它的世界环境和边界。没有关卡，你将遇到一个错误，看起来像这样：![Preparing the game for Box2D](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_2.jpg)

1.  为此，从`chapter4`文件夹的`level`子文件夹中复制`testsetup.js`脚本，并将其放在本地的`levels`文件夹中。将关卡添加到所需的文件中。

```js
'game.levels.testsetup'
```

1.  在主脚本的`init()`方法中插入一个`loadlevel()`函数。

```js
init: function() {
    this.loadLevel( LevelTestsetup );
  },
```

1.  在浏览器中重新加载游戏，你应该会看到**it works!**的消息。现在你已经看到了它，可以从代码中删除它。它在主脚本的`draw()`方法中。

```js
  var x = ig.system.width/2,
    y = ig.system.height/2;
    this.font.draw( 'It Works!', x, y, ig.Font.ALIGN.CENTER);
```

太好了！我们现在应该已经准备就绪了。我们要做的第一件事是建立一个小关卡，以便有一个属于自己的游乐场。

# 构建一个横向滚动的关卡

为了构建一个关卡，我们再次需要依赖于 ImpactJS Weltmeister：

1.  在浏览器中打开 Weltmeister `localhost/chapter4/Weltmeister.html`。我们没有任何实体可以玩耍，所以现在我们要添加的只是一些图形和一个碰撞层。这个碰撞层特别重要，因为 Box2D 扩展代码将寻找它，缺少它将导致游戏崩溃。可以说，对于 ImpactJS 来说，Box2D 仍处于起步阶段，这样的小 bug 是可以预料到的。

1.  添加一个层并将其命名为`collision`；Weltmeister 将自动识别它为碰撞层。

1.  将其瓷砖大小设置为`8`，层尺寸设置为`100 x 75`。现在我们有一个 800 x 600 像素的画布可以使用。

1.  现在在边缘画一个框，这样我们就有了一个封闭的环境，没有实体可以逃脱。当重力开始作用时，这将非常重要。没有坚实的地面，你肯定会得到一些意外的结果。

1.  现在添加一个新的层，将其命名为`background`。我们将使用一张图片作为这个关卡的背景。

1.  从`media`文件夹中选择`church.png`文件作为图块集。我们的图片是 800 x 600 像素，所以它应该恰好适合我们用碰撞层创建的区域。将瓷砖大小设置为`100`，层尺寸设置为`8 x 6`。在画布上绘制教堂的图片。

1.  将你的关卡保存为`level1`。

太好了，我们现在有了一个基本的关卡。虽然它很空，但一些额外的障碍会很好。只需按照以下步骤添加一些障碍：

1.  添加另一个名为`platforms`的层。

1.  使用`tiles.png`文件作为图块集。它们设计简单，但可以作为任何你想构建的平台的基本构件。将瓷砖大小设置为`8`，尺寸设置为`100 x 75`，与碰撞层完全相同。

1.  在开始绘制平台之前，打开**与碰撞层链接**选项。这样，你就不需要事后用碰撞层追踪平台。如果你不希望平台的每个部分都是固体的，当然可以暂时关闭链接，绘制瓷砖，然后重新打开链接；链接不是事后建立的。

1.  在关卡中添加一些浮动平台；按照你的内心欲望来决定它们应该是什么样子。

1.  当你觉得舞台已经准备好时保存你的关卡。

1.  将关卡添加到你的`main.js`脚本的`require()`函数中。

```js
.requires(
  'impact.game',
  'impact.font',
  'plugins.box2d.game',

  'game.levels.testsetup',
  'game.levels.level1'
)
```

1.  确保在开始时加载名为`level1`的关卡，而不是我们的`testsetup`关卡，通过改变`loadLevel()`函数的参数。

```js
    init: function() {
    // Initialize your game here; bind keys etc.
    this.loadLevel( LevelLevel1 );
  },
```

![构建一个侧面滚动关卡](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_3.jpg)

现在是时候向游戏中添加一个可玩实体，这样我们就可以发现我们刚刚创建的令人惊叹的关卡了。

# 可玩角色

由于我们正在使用 Box2D，我们将不使用标准的 ImpactJS 实体，而是使用适应版本。特别是实体在 Box2D 世界中移动的方式是使一切变得不同的地方。在标准的 ImpactJS 中，这是将你的角色图像沿着某个方向移动几个像素的非常简单的过程。然而，Box2D 使用力；因此，为了移动，你需要克服重力甚至空气摩擦。但让我们先建立一个基本实体：

1.  打开一个新的 JavaScript 文件，并将其保存为`entities`文件夹中的`player.js`。

1.  添加基本的 Box2D 实体代码如下：

```js
ig.module(
  'game.entities.player'
)
.requires(
  'plugins.box2d.entity'
)
.defines(function(){
  EntityPlayer = ig.Box2DEntity.extend({
  });
});
```

1.  正如你所看到的，术语`entity`是 Box2D 实体的扩展，因此需要 Box2D 实体插件文件。再次确保遵守命名约定，否则你的玩家实体将不会出现在 Weltmeister 中。

1.  将`'game.entities.player'`参数添加到`main.js`脚本中。

如果你在进行这些修改后访问 Weltmeister，你会发现玩家在你的实体层中。尽管目前它只是一个不可见的正方形，你无法控制它。是时候通过添加一个动画表来改变他的不可见性了。

```js
EntityPlayer = ig.Box2DEntity.extend({
  size: {x: 16, y:24},
  name: 'player',
  animSheet: new ig.AnimationSheet( 'media/player.png', 16, 24 ),
  init: function( x, y, settings ) {
    this.parent( x, y, settings );
    this.addAnim( 'idle', 1, [0] );
    this.addAnim( 'fly', 0.07, [1,2] );
  } 
});
```

通过上面的代码块，我们给玩家指定了大小和名称；但更重要的是，我们添加了图形。动画表只包含两个图像，一个是玩家站立不动时的图像，另一个是玩家飞行时的图像。这并不多，但对于一个简单的游戏来说足够了。侧面滚动游戏在需要图形方面有相当大的优势。理论上，你只需要两张图像来代表一个角色；也就是说，一个是角色静止不动时的图像，另一个是角色在运动时的图像。而对于一个俯视游戏，你至少需要六张图像来完成同样的事情。这是因为，除了侧视图，你还需要一个角色背面和正面的图像。因此，如果你为玩家开火添加一个动画，这将导致侧面滚动游戏需要额外绘制一张图像，而俯视游戏需要三张图像。很明显，如果你只有有限的资源来获取你的图形，侧面滚动游戏更好。

现在我们可以将玩家添加到游戏中并且他实际上是可见的，但我们还没有对他有任何控制。

玩家控制是在两个地方完成的，即主脚本和玩家脚本。在主脚本中，将控制添加到游戏的`init()`方法中。

```js
init: function() {
    // Bind keys
    ig.input.bind(ig.KEY.LEFT_ARROW, 'left' );
    ig.input.bind( ig.KEY.RIGHT_ARROW, 'right' );
    ig.input.bind( ig.KEY.X, fly);
//Load Level
    this.loadLevel( LevelLevel1 );
  },
```

在玩家脚本中，我们需要改变我们的`update()`函数，这样玩家就可以对我们的输入命令做出反应。

```js
update: function() {
  // move left or right
  if( ig.input.state('left') ) {
    this.body.ApplyForce( new b2.Vec2(-20,0),this.body.GetPosition() );
    this.flip = true;
  }
  else if( ig.input.state('right') ) {
    this.body.ApplyForce( new b2.Vec2(20,0),this.body.GetPosition() );
    this.flip = false;
  }
  // jetpack
  if( ig.input.state('fly') ) {
    this.body.ApplyForce( new b2.Vec2(0,-60),this.body.GetPosition() );
    this.currentAnim = this.anims.fly;
  }
  else {
    this.currentAnim = this.anims.idle;
  }
  this.currentAnim.flip.x = this.flip;
  this.parent();
}
```

在 Box2D 中，实体有一个额外的属性，即身体。为了移动身体，我们需要对其施加力。这正是当我们使用身体的`ApplyForce()`方法时发生的事情。我们在某个方向上施加一个力，因此我们实际上使用一个向量。向量的使用正是 Box2D 的全部内容。只要我们保持右、左或飞行按钮按下，力就会被施加。然而，当释放时，实体并不会立即停止。不再施加进一步的力，但需要一定的时间来消耗施加力的效果；这与我们在前几章中使用的速度有很大的不同。

如果你把玩家添加到关卡中，确保他在左上角的某个平台上。左上角是默认可见的，我们还没有一个适应性视口来跟随我们的玩家。准确地说，他现在并不需要一个平台来站立，因为我们的世界没有重力。让我们解决这个问题。在`main.js`脚本中添加重力属性到你的游戏，如下所示：

```js
MyGame = ig.Box2DGame.extend({
  gravity: 100,
```

让我们带我们的玩家进行一次测试飞行，好吗？

![可玩角色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_4.jpg)

你可能已经注意到，即使他飞行得相当顺利，我们的喷气背包青蛙遇到的任何固体物体都会使他旋转。也许你实际上不希望发生这种情况。特别是当他的头朝下时，他的喷气背包火焰朝上。现在，如果激活喷气背包仍然导致向上推力，那么喷气背包火焰朝上就没有太多意义。因此，我们需要解决他的稳定性问题。这可以通过在水平轴上固定身体来实现。将以下代码添加到青蛙的`update()`函数中：

```js
this.body.SetXForm(this.body.GetPosition(), 0);
```

现在玩家的身体被固定在 0 度角朝向 x 轴。尝试将其更改为 45；现在你有一个疯狂的青蛙，即使面向左，他的身体也始终向右倾斜飞行。

现在我们有一个飞行和稳定的青蛙。只可惜当我们向右移动一点或重力把我们带到关卡的底部时，我们就看不到他了。现在绝对是引入一个跟随摄像头的时候了。为此，我们需要对游戏的`update()`函数进行修改，如下所示：

```js
update: function() {
    this.parent();
    var player = this.getEntitiesByType( EntityPlayer )[0];
    if( player ) {
      this.screen.x = player.pos.x - ig.system.width/2;
      this.screen.y = player.pos.y - ig.system.height/2;
    }
},
```

玩家被放在一个局部变量中，并且每帧检查其位置以更新屏幕的位置。因为我们从玩家的位置中减去视口大小的一半，所以我们的玩家被整齐地保持在屏幕中央。如果不减去这部分，玩家将保持在屏幕的左上角。

保存所有修改并在你创建的关卡周围飞行；尽情享受宁静，因为很快敌对势力将搅乱这个地方。

让我们快速回顾一下我们关于 Box2D 实体以及如何使用它制作可玩角色的内容。Box2D 实体不同于 ImpactJS 实体，Box2D 利用向量来移动。向量是方向和力的组合：

+   打开一个新的 JavaScript 文件，并将其保存为`player.js`。

+   插入标准的 Box2D 实体扩展代码。

+   在主脚本中包含玩家实体。

+   为玩家添加动画。还利用`flip`属性，它可以在垂直轴上翻转图像，并为侧向滚动游戏剪切所需的角色图形的一半。

+   添加玩家控制，使其能够向左、向右和向上移动。注意力是如何施加在身体上以便移动的。一旦输入按钮被释放，不再施加力，实体将继续前进并完全停止，一旦力完全消散或者他撞到一个固体墙壁。

+   将重力引入游戏的属性。由于重力是一个不断向下的恒定力量，它会将一切拉向它遇到的第一个固体物体，除非提供一个相反的力。对于我们的飞行青蛙，他的喷气背包是对抗重力的反作用力。

+   我们的青蛙目前还不知道如何稳定地飞行。将他固定在水平轴上，这样他每次撞到固体物体时就不会旋转。

+   最后，我们需要一个摄像机来跟踪我们的位置。在游戏的`update()`函数中加入自动跟随摄像机。

# 添加一个小敌人

我们需要一些对手，一些我们可以在拥有武器后击落的东西。因此，让我们介绍一些更多的青蛙！这次是敌对的：

1.  打开一个新文件，保存为`enemy.js`。

1.  将以下代码插入文件中。这是在 Weltmeister 中获得我们敌人表示所需的最小代码。因此，它已经包括了动画表。

```js
ig.module(
  'game.entities.enemy'
)
.requires(
  'plugins.box2d.entity'
)
.defines(function(){
EntityEnemy = ig.Box2DEntity.extend({
size: {x: 16, y:24},
name: 'enemy',
animSheet: new ig.AnimationSheet( 'media/enemy.png', 16, 24),
init: function( x, y, settings ) {
  this.parent( x, y, settings );
  // Add the animations
  this.addAnim( 'idle', 1, [0] );
  this.addAnim( 'fly', 0.07, [1,2] );
  }
})
});
```

1.  在我们的`main.js`脚本中需要敌人实体。

```js
'game.entities.enemy'
```

1.  使用 Weltmeister 在关卡中添加敌人。

由于我们的敌人目前相当无助，我们也可以将他从平台上击落。

![添加一个小敌人](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_5.jpg)

在正常的 ImpactJS 代码中，我们必须为此设置碰撞变量，否则玩家和敌人青蛙会直接穿过彼此。在 Box2D 中，这是不必要的，因为碰撞会自动假定，并且我们的飞行青蛙撞到每个可移动对象时都会施加力。

由于我们已经有了重力，一个很好的替代方法是在关卡顶部生成敌人。在游戏的`init()`函数中添加`spawnEntity()`函数。敌人将在那里生成，并且重力会将其拉到底部。

```js
this.loadLevel( LevelLevel1 );
this.spawnEntity('EntityEnemy',300,30,null);
```

确保`spawnEntity()`函数在关卡加载后使用，否则会出错。一旦敌人有了自己的智能，在关卡顶部生成敌人就会更有意义。它们会下落，要么落到最底部，要么直到它们到达一个平台，在那里它们会等待玩家并攻击它。

一旦我们为红色青蛙提供了一些基本的人工智能，我们将把它变成一个真正讨厌的生物。然而，让我们首先通过向游戏添加一些武器来做好准备。

让我们简要回顾一下我们是如何创建我们的敌人的：

+   打开一个新的 JavaScript 文件，保存为`enemy.js`。

+   插入标准的 Box2D 实体扩展，附加动画表，并添加动画序列

+   在主脚本中包含敌人实体

+   使用 Weltmeister 和`spawnentity()`方法在关卡中添加敌人

# 引入强大的武器

武器很棒，特别是如果它们受到重力的影响，或者如果它们可以对其他实体施加一些力。我们将在这里看两种类型的武器，即抛射物和炸弹。

## 发射抛射物

抛射物将是我们对手青蛙的主要武器，所以让我们从设置基础开始：

1.  打开一个新的 JavaScript 文件，保存为`projectile.js`，放在`entities`文件夹中。

1.  使用以下代码片段添加基本的 Box2D 实体代码，包括动画表和序列：

```js
ig.module(
  'game.entities.projectile'
)
.requires(
  'plugins.box2d.entity'
)
.defines(function(){
  EntityProjectile = ig.Box2DEntity.extend({
  size: {x: 8, y: 4},
  lifetime:60,
  name: 'projectile',
  animSheet: new ig.AnimationSheet( 'media/projectile.png', 8, 4),
  init: function( x, y, settings ) {
    this.parent( x, y, settings );
    this.addAnim( 'idle', 1, [0] );
  }
});
});
```

1.  除了名称、大小和执行动画所需的元素之外，我们已经包括了一个名为`lifetime`的属性。每个抛射物都以`60`的`lifetime`开始。当它达到`0`时，我们将使其消失并杀死子弹。这样我们就不会在一个游戏中得到过多的实体。每个实体都需要自己的计算，一次在屏幕上有太多实体可能会显著降低游戏的性能。可以使用 ImpactJS 调试器来跟踪这种性能，通过在主脚本中包含`'impact.debug.debug'`命令来打开它。

1.  将`game.entities.projectile`脚本添加到`main.js`脚本中。

现在我们可以通过 Weltmeister 向游戏中添加抛射物。然而，手动添加对我们来说没有太大用处。让我们改变玩家的代码，这样我们的青蛙就可以生成抛射物。首先，在主脚本中将`'shoot'`状态绑定到一个键。

```js
ig.input.bind(ig.KEY.C, 'shoot' );
```

然后将以下代码添加到玩家的`update()`函数中。

```js
if(ig.input.pressed('shoot') ) {
  var x = this.pos.x + (this.flip ? -0 : 6);
  var y = this.pos.y + 6;
  ig.game.spawnEntity( EntityProjectile, x, y, {flip:this.flip} );
}
```

生成弹丸需要在特定位置完成，并且必须指向特定方向，要么向左，要么向右。我们任意地将生成点的 y 坐标设置为比我们的玩家位置低 6 像素；我们也可以将其设置为 10、20 或 200 像素。不过，在最后一种情况下，子弹看起来会生成在玩家下方，这会显得相当不寻常。不过，我们不要忘记玩家的位置总是在其图像的左上角。鉴于我们的青蛙的高度为 24 像素，看起来就好像子弹是从嘴里射出来的，这对于一只青蛙来说相当酷。x 坐标是另一回事。如果青蛙面向左，我们不调整生成坐标；如果他面向右，我们将其调整 6 像素。有关玩家是否翻转的信息不仅用于调整生成坐标。它还作为一个可选的输入参数传递给弹丸本身。这里将用它来确定它应该面向和飞向哪一边。在发射子弹时，你可能会注意到青蛙被击退了一点，有点像枪的后坐力。这是因为青蛙最初占据了子弹生成时的位置。如果你想避免这种酷炫的效果，你只需要让子弹离青蛙远一点。如果你此时加载游戏，你会注意到你的子弹生成了，但没有飞走。这是因为我们没有告诉子弹在生成时应该这样做。

将以下两行代码添加到弹丸的`init()`函数中将纠正这种情况。

```js
this.currentAnim.flip.x = settings.flip;
var velocity = (settings.flip ? -10 : 10);
this.body.ApplyImpulse( new b2.Vec2(velocity,0),
this.body.GetPosition() );
```

在生成弹丸时，我们现在应用的是冲量而不是力。`ApplyImpulse()`和`ApplyForce()`函数之间存在显著的区别。`ApplyForce()`函数在物体上施加一个恒定的力，而`ApplyImpulse()`函数只施加一次，但是突然。你可以将其比作推动一块石头与跑向它并用你所有的力量和动量撞击它。现实生活中的子弹与我们在这里尝试模拟的方式相同；它被一个小爆炸甩开，之后再也没有被推动。局部变量`var.velocity`用于调整子弹的方向，就像动画取决于`settings.flip`参数的值一样。如果`flip`属性的值为 false，子弹将面向右并向右飞行。如果`flip`属性的值为 true，动画将翻转，使其面向左。因为速度取负数，子弹也会向左飞行。

我们仍然可以调整 y 轴上的冲量，目前设置为`0`。输入一个负数将使我们的青蛙向上射击，就像一门防空炮。输入一个正数将使他向下射击，就像一架轰炸机。尝试调整这个值，看看效果。

我们的弹丸仍然在屏幕上徘徊，因为我们还没有充分利用我们的`lifetime`属性。

让我们修改`update()`函数，以限制我们子弹的寿命。

```js
update: function(){
  this.lifetime -=1;
  if(this.lifetime< 0){this.kill();}
  this.parent();
}
```

每当游戏通过更新循环，也就是每帧一次，弹丸的剩余寿命就会减少 1。在每秒 60 帧的游戏中，给定一个总寿命值为 60，子弹在生成后有 1 秒的寿命。

我们可以用它向敌人射击，并且实际上用子弹的力量将他们推开，但我们还没有真正伤害到他们。要实现这一点，我们需要检查是否击中了敌人。

```js
check: function(other){
  other.receiveDamage(10);
  this.kill();
}
```

添加这个修改后的`check()`函数，这将使弹丸在自毁之前造成伤害，是不够的。尽管碰撞是由 Box2D 自动处理的，但`check()`函数工作所需的参数并没有。我们需要做一些其他的事情：

1.  通过添加`TYPE`属性，告诉敌人它是 B 型实体。

```js
type: ig.Entity.TYPE.B,
```

1.  使用`checkAgainst`属性使抛射物检查与 B 类型实体的碰撞。

```js
checkAgainst: ig.Entity.TYPE.B,
```

1.  现在保存并重新加载游戏。你现在可以杀死那些讨厌的红色青蛙了。

尝试将你的玩家设为 B 类型实体。现在你的子弹会杀死你。这是因为我们让它们生成在我们的青蛙已经占据的空间中。正如我们之前看到的，这也是为什么我们在发射子弹时有这种后坐力效应的原因。然而，这次不仅仅是后坐力；它实际上可以杀死玩家。所以我们最好不要让我们的玩家成为 B 类型实体，或者我们应该让我们的子弹生成得离得更远，失去后坐力效应。拥有一些可以自卫的东西是很好的，即使其他青蛙现在还不构成太大的威胁。在让它们活过来之前，我们很快要看一下更爆炸性的东西，一个炸弹。

在转向炸弹之前，让我们再快速看一下我们是如何引入我们的主要武器——子弹的：

+   我们需要枪，很多枪。

+   打开一个新的 JavaScript 文件，并将其保存为`projectile.js`。

+   插入标准的 Box2D 实体扩展，附加一个动画表，并添加动画序列。还添加一个`lifetime`属性，用来跟踪子弹在游戏中应该停留多久。

+   在主脚本中包含抛射实体。

+   在主脚本中为射击输入状态添加一个键绑定。

+   当玩家点击射击按钮时，让我们的飞行青蛙产生一个抛射物。

+   给子弹添加一个冲量，这样它就可以真正飞起来，而不仅仅是掉到地上。

+   检查子弹在空中的时间，并在超过预设寿命时将其销毁。

+   让子弹检查敌人。如果遇到敌人，它应该造成伤害并自杀。

+   尝试让子弹杀死玩家，但不要保持这种状态。

## 制造一个真正的炸弹

制造炸弹的基础与制造抛射物的基础相同，实际上，它们与创建任何实体的基础相同：

1.  打开一个新的 JavaScript 文件，并将其保存为`bomb.js`在`entities`文件夹中

1.  添加基本的 Box2D 实体代码，动画表和序列如下：

```js
ig.module(
  'game.entities.bomb'
)
.requires(
  'plugins.box2d.entity'
)
.defines(function(){
EntityBomb = ig.Box2DEntity.extend({
  size: {x: 24, y: 10},
  type: ig.Entity.TYPE.A,
  checkAgainst: ig.Entity.TYPE.B,
  animSheet: new ig.AnimationSheet( 'media/bomb.png', 24, 10 ),
  lifespan: 100,
  init: function( x, y, settings ) {
    this.parent( x, y, settings );
    // Add the animations
    this.addAnim( 'idle', 1, [0] );
    this.currentAnim = this.anims.idle;
  }
});
});
```

1.  这次我们已经给我们的炸弹一个类型和一个用于造成伤害的检查类型

1.  将`game.entities.bomb`参数作为所需实体放入`main.js`脚本

现在我们有一个炸弹，我们可以把它放在任何我们想要的关卡中。我们可以在我们的关卡天花板附近添加一些炸弹，这样它们在关卡加载时会掉下来。那将是很棒的，因为会有一个真正的爆炸。我们将把这个爆炸作为一个单独的方法引入，只有我们的炸弹才能使用。

```js
explosion:
function(minblastzone,maxblastzone,blastdamage,blastforcex,blastforcey){
  varEnemyList= ig.copy(ig.game.entities);
  var i = 0;
  //check every entity
  while(typeofEnemyList[i] != 'undefined'){
    Enemy = EnemyList[i];
    //calculate distance to entity
    distance = Math.sqrt((this.pos.x - Enemy.pos.x)*(this.pos.x -Enemy.pos.x) + (this.pos.y - Enemy.pos.y)*(this.pos.y -Enemy.pos.y));
    //adjust blastdirection depending on entity position
    if(this.pos.x - Enemy.pos.x< 0){adjustedblastforcex =blastforcex}
    else{adjustedblastforcex = - blastforcex}
    if(this.pos.y - Enemy.pos.y< 0){adjustedblastforcey = blastforcey}
    else{adjustedblastforcey = - blastforcey}//if within blastzone: blow up the targetif(minblastzone< distance && distance <maxblastzone){Enemy.body.ApplyImpulse(newb2.Vec2(adjustedblastforcex,adjustedblastforcey),this.body.GetPosition());
      Enemy.receiveDamage(blastdamage,this);}
      i++;
    }
}
```

就像`init()`、`update()`和`check()`方法一样，我们现在将`explosion()`方法插入到炸弹实体中，以便它今后能够使用。`explosion()`方法接受五个参数：

1.  **最小爆炸区域**：如果一个实体距离比这更近，他将不会受到影响。这对于炸弹来说并没有太多意义，除非它允许你在一个炸弹中使用几次爆炸。这反过来又使得在目标靠近炸弹时造成更大的伤害，而在目标远离炸弹时造成更小的伤害成为可能。

1.  **最大爆炸区域**：距离最大爆炸区域以外的一切都不会受到爆炸的影响。

1.  **爆炸伤害**：这是实体在爆炸区域内会受到的伤害。

1.  **Blastforcex**：这是应用于受影响实体的 x 轴冲量。它将决定目标会向右或向左飞多远。

1.  **Blastforcey**：这是应用于受影响实体的 y 轴冲量。它将决定目标会飞多高。显然，如果目标在炸弹下方爆炸，它会将目标向下推，而不是向上。

`explosion()` 方法的工作方式如下。所有实体都被复制到一个本地变量中。然后依次检查这些实体，看看它们距离炸弹有多远。这里计算的距离是欧几里得距离。在计算欧几里得距离或普通距离时，你应用毕达哥拉斯定理。这个定理规定，如果已知三角形的另外两边的长度，就可以计算出一个直角三角形的任意一边的长度。公式是 *a² + b² = c²*，其中 *c* 是三角形的最长边。根据不幸的目标是位于炸弹的右侧还是左侧，上方还是下方，力的方向会进行调整。最后，函数检查距离是否在爆炸区域的范围内。如果是这样，就对目标施加伤害和冲量。在这一点上，实体要么死亡，要么飞向空中；无论哪种情况都不是好消息。

仅仅添加这个 `explosion()` 方法是没有用的，直到我们真正使用它。因此，我们需要修改我们的 `update()` 方法，以便在炸弹寿命结束时引爆我们的炸弹。

```js
update: function(){
  //projectiles disappear after 100 frames
  this.lifespan -= 1;
  if(this.lifespan< 0){
    this.explosion(0,40,70,200,100);
    this.explosion(40,200,20,100,50);
    this.kill();
  }
  this.parent();
},
```

寿命部分的工作方式与弹丸中的方式完全相同。然而，在这种情况下，我们不仅仅调用 `kill()` 函数，而是使用我们新开发的爆炸两次。我们可以只调用一次函数，并将爆炸范围值设置在 0 到 200 之间。正如前面提到的，我们现在的优势在于高伤害和靠近炸弹的压力之间的区分，以及低伤害和远离炸弹的压力。从技术上讲，我们可以使用任意数量的爆炸；每一个都需要计算时间。不过，你可以决定你想要多少个爆炸。

在实际测试游戏中的爆炸之前，确保为所有实体分配健康值。它们是否能够承受爆炸的伤害将取决于你是否给予它们足够的健康值。由于默认值设置为 10，它们将不会飞走，而是立即死亡，如果使用前面的数字。因此，让我们通过在它们各自的 `init()` 函数之前添加此属性来给我们的玩家和敌人一个健康值为 100。

```js
health: 100
```

作为最后的修饰，我们可以让炸弹在接触到敌对青蛙之一时爆炸。

```js
check: function(other){
    other.receiveDamage(30);
    this.explosion(0,40,70,200,100);
    this.explosion(40,200,20,100,50);
    this.kill();
}
```

我们已经确保炸弹通过设置 `checkAgainst` 属性检查与 B 类型实体的接触。直接受到这块金属的伤害设置为 `30`。这之后是爆炸本身，它将造成 70 分的伤害，因为敌人离得很近。第二波爆炸影响到更远的一切，然后炸弹最终自毁。

现在我们有一个可以放置在关卡中任何位置并且效果很好的炸弹。然而，如果我们的玩家自己也能生成一个炸弹，那就更好了。在接下来的步骤中，我们简单地重复了我们在弹丸中所做的操作，使玩家自己生成一个炸弹：

1.  将一个键盘按钮分配给炸弹输入状态，如下行代码所示：

```js
ig.input.bind(ig.KEY.V, 'bomb');
```

1.  修改玩家的 `update()` 函数，以便玩家现在可以使用以下代码生成炸弹：

```js
if (ig.input.pressed('bomb')){
  var x = this.pos.x + (this.flip ? 0 : 8 );
  var y = this.pos.y + 25;
  ig.game.spawnEntity(EntityBomb,x,y, {flip:this.flip});
}
```

1.  这里定义的生成坐标与我们在弹丸中所做的不同。 `y` 坐标非常重要；它设置为 `25`，因为我们的飞行青蛙的高度为 `24` 像素。这样炸弹总是生成在飞行青蛙的正下方。

1.  将以下代码添加到炸弹的 `init()` 函数中，以便它接受 `flip` 参数，以知道生成时应该面向哪一侧。

```js
this.currentAnim.flip.x = settings.flip;
```

1.  保存、重新加载，并炸掉那些红色的青蛙！不过要小心，炸弹也可能杀死你。![Building an actual bomb](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_6.jpg)

炸弹是我们最大的武器；让我们快速回顾一下我们是如何构建它的：

+   打开一个新的 JavaScript 文件，并将其保存为 `bomb.js`。

+   插入标准的 Box2D 实体扩展，附加动画表，并添加动画序列。添加一个寿命属性，用于跟踪炸弹爆炸前剩余的时间，如果没有被触碰敌人而过早引爆。

+   在主脚本中包括炸弹实体。

+   在关卡中添加一个炸弹。

+   介绍`explosion()`方法；这是一个自定义函数，模拟爆炸的伤害和力量效果。

+   更改`update()`函数，使炸弹在时间到时爆炸。

+   使用`check()`函数检测与敌人的碰撞并立即引爆。

+   为炸弹分配一个键盘快捷键。

+   调整玩家的`update()`函数，使玩家命令时会生成一个炸弹。

+   使炸弹翻转到玩家所看的方向。

+   玩得开心，尽情地炸青蛙！

# 人工智能

是时候让我们的红色青蛙变得更聪明一点，这样他们至少有一点机会对抗我们新开发的武器库。在第三章中，*让我们建立一个角色扮演游戏*，我们完全按照书本上的方法做到了这一点，通过将决策与行为分开。我们为决策制定了一个单独的人工智能（AI）文件，而实际行为始终在实体的`update()`函数中。

这一次，我们将保持非常简单，直接将所有人工智能放在敌人的`update()`方法中。这将证明，即使是简单的人工智能也可以看起来相当聪明。

让我们用以下代码修改我们的敌人的`update()`函数：

```js
update: function(){
  var players = ig.game.getEntitiesByType('EntityPlayer');
  var player = players[0];
  // both distance on x axis and y axis are calculated
  var distanceX = this.pos.x - player.pos.x;
  var sign = Math.abs(distanceX)/distanceX;
  var distanceY = this.pos.y - player.pos.y;
  //try to move without flying, fly if necessary
  var col = ig.game.collisionMap.trace( this.pos.x, this.pos.y,player.pos.x, player.pos.y,16,8 );
  if (Math.abs(distanceX) < 110){
    var fY = distanceY> 0 ? -50: 0;
    this.body.ApplyForce( new b2.Vec2(sign * -20,fY),this.body.GetPosition() );
    if(distanceY>= 0){this.currentAnim = this.anims.fly;}
    else{this.currentAnim = this.anims.idle;}
  }
  this.body.SetXForm(this.body.GetPosition(), 0);
  if (distanceX> 0){this.currentAnim.flip.x = true;}
  else{this.currentAnim.flip.x = false;}
  this.parent();
  }
```

将此函数插入到敌人实体中，将使他试图抓住玩家。但它是如何工作的呢？首先，玩家实体保存在函数的本地变量中，称为`player`。计算敌人和玩家之间的水平距离和垂直距离。`sign`变量用于确定青蛙应该向左飞还是向右飞。他总是向上飞；如果他需要下降，因为玩家在他下面，他将让重力发挥作用。在飞行时，飞行动画是活动的，否则使用空闲动画，即使在水平移动时也是如此。

青蛙的身体固定在 x 轴上，以防止他旋转，就像玩家一样。最后，根据玩家相对于敌人的位置，动画会翻转到左侧或右侧。

现在我们有一只青蛙，如果我们离他足够近，他会跟着我们走。现在我们需要他对玩家造成一些伤害：

1.  确保敌人的类型和需要检查的类型分别填写为 B 和 A。还引入一个名为`cooldowncounter`的新敌人属性，如下所示：

```js
type: ig.Entity.TYPE.B,
checkAgainst: ig.Entity.TYPE.A,
cooldowncounter: 0,
```

1.  `cooldowncounter`属性将跟踪自上次青蛙能够造成伤害以来经过了多少帧。

1.  `cooldowncounter`属性必须计数，因此将其添加到`update()`函数中：

```js
this.cooldowncounter ++;
```

1.  扩展`check()`函数，以检查自上次攻击以来是否已经过了足够的帧数，并允许青蛙进行攻击，如下所示：

```js
check: function(other){
  if (this.cooldowncounter> 60){
    other.receiveDamage(10,this);
    this.cooldowncounter = 0;
  }
}
```

青蛙现在将能够在玩家身上使用其恶毒的近战攻击。无论青蛙在近距离对玩家造成的攻击是什么，每次击中玩家都会降低玩家的健康值 10 点。现在玩家肯定需要避开这些恶毒的生物，以免健康值迅速下降。我们需要给玩家一些额外的东西，让他能够在这场屠杀中生存下来。

人工智能是使敌人值得对抗的原因。与我们在第三章中提到的不同，*让我们建立一个角色扮演游戏*，它并不总是需要变得复杂。让我们快速看一下我们如何为横向滚动游戏实现了人工智能：

+   更改`update()`函数，使敌人现在可以朝着玩家飞行。这个新的`update()`函数是敌人青蛙的人工智能。与第三章中的*让我们建立一个角色扮演游戏*不同，这次决策和行为都包含在同一段代码中。

+   引入一个冷却计数器，用于跟踪自上次攻击以来的帧数。还要确保敌人实体是 B 类型，并检查它是否接触到 A 类型的实体。玩家应该是 A 类型的实体。

+   通过将其添加到修改后的`update()`函数中，使`cooldown`属性在每帧过去时增加 1 的值。

+   在`check()`函数中加入攻击，使青蛙成为不可忽视的力量。

# 拾取物品

我们的小飞行青蛙现在正式可以被那些讨厌的红色青蛙杀死。这对他来说不是好消息，我们需要提供一种方式来补充失去的健康。这是通过使用拾取物品来实现的，也就是，当接触到玩家时会消失但在过程中提供有益效果的实体。

在我们添加实际的拾取物品之前，它将以补充健康的板条箱的形式出现，让我们先在游戏中添加一个普通的板条箱。

## 添加一个普通板条箱

我们的板条箱将作为我们可以发明的所有类型的板条箱的原型。执行以下步骤创建板条箱：

1.  打开一个新文件并将其保存为`crate.js`。

1.  将板条箱代码添加到文件中。

```js
ig.module(
  'game.entities.crate'
)
.requires(
  'plugins.box2d.entity'
)
.defines(function(){
EntityCrate = ig.Box2DEntity.extend({size: {x: 8, y: 8},
  health: 2000,
  name: 'crate',
  type: ig.Entity.TYPE.B,checkAgainst: ig.Entity.TYPE.A,
  animSheet: new ig.AnimationSheet( 'media/crate.png', 8, 8),
  init: function( x, y, settings ) {
    this.addAnim( 'idle', 1, [0] );
    this.parent( x, y, settings );
  }
});
});
```

1.  这段代码非常简单，因为板条箱只是一个无生命的物体。尽管是一个坚固的无生命物体，因为它的健康值为`2000`。通过给予板条箱如此多的健康，它能够经受住多次炸弹爆炸。

1.  保存文件并在 Weltmeister 中添加一些到你的游戏中。当然，在释放爆炸之前，试着堆叠几个板条箱。![添加一个普通板条箱](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_8.jpg)![添加一个普通板条箱](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_9.jpg)

现在我们有了标准的板条箱；制作一个治疗板条箱只需要几个步骤，因为我们将在普通板条箱的基础上构建它。

在看看我们的治疗板条箱之前，让我们快速看看我们是如何制作普通板条箱的：

+   创建一个新文件并将其保存为`crate.js`

+   实现标准的 Box2D 实体代码

+   保存并使用 Weltmeister 向游戏中添加一些板条箱

## 实现一个治疗板条箱

现在我们有了基本的原型板条箱，我们只需要在其基础上构建，以创建健康板条箱。执行以下步骤来构建健康板条箱：

1.  打开一个新文件并将其保存为`crate.js`。

1.  为其添加`healthcrate`特定的代码。健康板条箱是普通板条箱的扩展，不是一个 Box2D 实体；因此，我们只需要指出健康板条箱与普通板条箱的区别所在：

```js
ig.module(
  'game.entities.healthcrate'
)
.requires('game.entities.crate'
).defines(function(){
EntityHealthcrate = EntityCrate.extend({
  name: 'healthcrate',
  animSheet: new ig.AnimationSheet( 'media/healthcrate.png', 8, 8),
  check: function(other){
    if(other.name == 'player'){
      other.health =  other.health + 100;
      this.kill();
    }
  }
})
});
```

1.  它有另一个名称和动画表。此外，它将治疗玩家并在治疗玩家后销毁自己。

1.  使用以下代码将板条箱添加到主脚本中，这样你的游戏就知道它在那里。

```js
'game.entities.healthcrate'
```

1.  保存并添加一个板条箱到游戏中以查看其效果。![实现一个治疗板条箱](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_10.jpg)

这个板条箱通过提供**100**的**健康**值来治疗玩家，如下截图所示。因此，玩家的健康值总是比游戏开始时更高。这只是一个选择；你可以通过实现健康上限来改变这一点，以确保治疗不会使玩家比初始状态更强大。

![实现一个治疗板条箱](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_12.jpg)

记住你可以随时用带有 Firebug 附加组件的 Firefox 打开并查找**文档对象模型**（**DOM**）中的玩家属性。在拾取板条箱之前，我们的玩家的健康值为 100，拾取后上升到 200。

治疗板条箱比普通板条箱要复杂一些。让我们再次看看我们制作治疗板条箱所采取的步骤：

+   创建一个新文件并将其保存为`healthcrate.js`。

+   扩展先前构建的生命箱，而不是一个 Box2D 实体。只添加健康箱与原始箱不同的参数。这包括一个`check()`函数，用于查看玩家是否触摸到它。

+   保存并添加一个生命箱到游戏中使用 Weltmeister。

+   在 DOM 中检查您的生命箱是否实际增加了玩家的生命值。

# 保持得分

在游戏中跟踪分数是一件相当简单的事情。为了实现一个系统，在其中每次杀死一个敌人时都会保持并增加分数，我们需要三样东西：

1.  我们需要一个在游戏本身范围内并且可以被视为某种开销变量的变量。

```js
.defines(function(){
GameInfo = new function(){
 this.score = 0;
},
MyGame = ig.Box2DGame.extend({
```

1.  这非常重要，因为正如我们将在第五章中看到的那样，*为您的游戏添加一些高级功能*，开始和结束屏幕实际上是正在加载的不同游戏。当新游戏加载到内存中时，旧游戏被丢弃，它的所有变量也被丢弃。这就是为什么我们需要一个存在于游戏之外的变量。

1.  这个函数用于增加一定数量的分数。这个函数允许是游戏本身的一个方法。只需将其插入到`MyGame`文件的其他主要函数下面的主脚本中。

```js
increaseScore: function(points){
  //increase score by certain amount of points
  GameInfo.score +=points;
}
```

1.  我们覆盖了敌人的`kill()`函数，如所示，因此青蛙不仅死亡，而且还为我们提供了额外的分数。

```js
  kill: function(){
    ig.game.increaseScore(100);
    this.parent();
  }
```

从现在开始，每当红蛙死亡时，我们都会得到额外的 100 分，并且这些分数会安全地保存在一个变量中，只要我们不刷新页面，它们就不会被删除。然后，我们可以稍后使用这个变量，在游戏结束时向我们的玩家提供一些反馈，告诉他表现得好还是差。

保持得分对于几乎任何游戏来说都是非常重要的组成部分。这是一种挑战玩家重玩游戏并在其中表现更好的方式。而且实现起来也不是太困难；让我们看看我们做了什么：

+   在当前游戏之外创建一个变量，并将变量命名为`score`

+   添加一个可以直接操作我们的`score`变量的游戏函数

+   敌人死亡时调用该函数，将分数添加到整体玩家得分中。

# 从一个级别过渡到另一个级别

为了实现地图过渡，您首先需要第二个级别。您可以自己制作一个，或者从本章的可下载文件中复制一个。您还需要触发器结束`levelchange`实体。将这两个实体复制到`entities`文件夹中，并将名为`level 2`的级别复制到本地计算机上的`levels`文件夹中。或者，您可以自己设计第二个级别，并使用随 Impact 许可证提供的触发器实体。触发器实体不是实际引擎的一部分；它可以在 ImpactJS 网站的可下载示例中找到。

在`levelchange`实体中，我们将进行以下代码更改：

```js
ig.module(
  'game.entities.levelchange'
)
.requires(
  'impact.entity'
)
.defines(function(){ 
EntityLevelchange = ig.Entity.extend({
  _wmDrawBox: true,
  _wmBoxColor: 'rgba(0, 0, 255, 0.7)',
  _wmScalable: true,
  size: {x: 8, y: 8},
  level: null,
  triggeredBy: function( entity, trigger ) {
    if(this.level) { 
      varlevelName = this.level.replace(/^(Level)?(\w)(\w*)/, function( m, l, a, b ) {
        return a.toUpperCase() + b;
        });
      var oldplayer = ig.game.getEntitiesByType( EntityPlayer )[0];
      ig.game.loadLevel( ig.global['Level'+levelName] );
      var newplayer = ig.game.getEntitiesByType( EntityPlayer )[0];
      newplayer = oldplayer;
    }
  },
  update: function(){}
});
});
```

正如您可能注意到的那样，它与我们在 RPG 中使用的不同，主要有两个方面：

+   它不考虑使用生成点。对于大多数横向卷轴游戏，实际上并不需要使用生成点。这是因为一旦完成了一个级别，您只能通过重新玩它来返回到它。因此，我们不需要每个级别多个生成点，只需要一个生成点。然而，如果我们只需要一个生成点，不使用我们在之前章节中使用的 Void 实体会更容易。相反，我们只需将玩家实体放在级别内的某个位置，级别将始终从那里开始。

+   对`levelchange`实体的第二个更改是我们对玩家实体的备份。在加载关卡之前，我们将玩家实体复制到一个名为`oldplayer`的本地变量中。一旦游戏加载，就会创建一个新的可玩角色；这是我们手动添加到 Weltmeister 中的`level 2`。然后我们将这个新玩家分配给另一个名为`newplayer`的本地变量。通过用`oldplayer`覆盖`newplayer`，我们可以继续使用旧的青蛙进行游戏。如果玩家被允许保留先前获得的补充武器或生命值，这可能很重要。

现在我们所需要做的就是在`level 1`中正确设置`trigger`和`levelchange`实体，这样我们就有了一个体面的关卡过渡。应该按照以下步骤进行：

1.  一旦`trigger`和`levelchange`实体出现在`entities`文件夹中，就将它们都添加到主脚本中。一旦你创建或复制了`level 2`，也将`level 2`添加到脚本中。

```js
'game.levels.level2',
'game.entities.trigger',
'game.entities.levelchange'
```

1.  使用 Weltmeister 将`trigger`和`levelchange`实体放入`level 1`。

1.  使用 Weltmeister 为`levelchange`实体添加一个值为`tolevel2`的`name`属性和一个值为`level2`的`level`属性。

1.  使用 Weltmeister 为`trigger`实体添加一个名为`target.1`的属性，值为`tolevel2`。

1.  仔细检查你的第二个关卡中是否有一个玩家实体，并且这个关卡的名称是`level2`。

1.  保存你所做的所有更改，并重新加载游戏进行测试。一定要尝试在使用关卡过渡之前收集一个生命值箱。一旦你到达`level2`，你的生命值增加应该会持续。

如果你从可下载文件中复制了`level2`，请注意星星的移动速度比飞船慢，而飞船的移动速度又比其他一些飞船慢。这是因为这三个图层的距离。如果你打开 Weltmeister，你会发现星星图层的距离值为**5**，最接近的星船的值为**2**，其他飞船的值为**3**。使用距离可以为视差游戏带来非常好的效果；明智地使用它们。

![从一个级别过渡到另一个级别](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_13.jpg)

如果只是单向进行关卡过渡，那么添加关卡过渡可以相对容易地完成。让我们回顾一下我们是如何做到这一点的：

+   复制`trigger`和`levelchange`实体。

+   构建或复制一个名为`level2`的第二个关卡。确保在关卡中添加一个玩家实体。

+   在主脚本中包括新的关卡和`trigger`和`levelchange`实体。

+   在`level 1`中添加一个`trigger`和`levelchange`实体，连接它们，并确保`levelchange`实体指向`level2`。

+   在设计关卡时，尝试使用图层的`distance`属性。这可以在横向滚动游戏中给你美丽的结果。

# 最后的战斗

每个好游戏都以一个具有挑战性的最终战斗结束，善良战胜邪恶，或者反之，由你决定。

为了进行一场具有挑战性的战斗，让我们创建一个单独的`boss`实体，比我们其他的青蛙更强大。

1.  新建一个文件并将其保存为`boss.js`。

1.  boss 将是我们正常敌人的扩展，所以让我们首先定义他与红色青蛙不同的特征。

```js
ig.module(
  'game.entities.boss'
)
.requires(
  'game.entities.enemy'
)
.defines(function(){
  EntityBoss = EntityEnemy.extend({
  name: 'boss',
  size: {x: 32, y:48},
  health: 200,
  animSheet: new ig.AnimationSheet( 'media/Boss.png', 32,48 )
});
});
```

1.  他的名字不同；但更重要的是，他的生命值更多，比其他青蛙要大得多。

1.  使用以下代码将 boss 添加到你的主脚本中：

```js
'game.entities.boss'
```

1.  保存所有更改并将 boss 放入你的一个关卡中。

我们现在确实有一个更大的敌人，生命值更多，基本上做的事情和较小的一样。这并不会让 boss 战变得有趣，所以让我们赋予他像玩家一样发射子弹的能力。我们需要一个单独的子弹实体，因为我们的基本抛射物只能伤害 B 类型实体，而我们的玩家是 A 类型；另外我们可能希望它看起来有点不同：

1.  新建一个文件并将其保存为`bossbullet.js`。

1.  这颗子弹将是普通子弹的直接扩展，除了类型检查和外观方式。编写以下代码来创建新的子弹实体：

```js
ig.module(
  'game.entities.bossbullet'
)
.requires(
  'game.entities.projectile'
)
.defines(function(){
  EntityBossbullet = EntityProjectile.extend({
  name: 'bossbullet',
  checkAgainst: ig.Entity.TYPE.A,
  animSheet: new ig.AnimationSheet( 'media/bossbullet.png',8, 4 )
  });
});
```

1.  我们需要进行最后一个修改，如下所示的代码，让 boss 发射自己的子弹：

```js
update: function(){
  var players = ig.game.getEntitiesByType('EntityPlayer');
  var player = players[0];
  // both distance on x axis and y axis are calculated
  var distanceX = this.pos.x - player.pos.x;
  var sign = Math.abs(distanceX)/distanceX;
  var distanceY = this.pos.y - player.pos.y;
  //try to move without flying, fly if necessary
  if (Math.abs(distanceX) < 1000 &&Math.abs(distanceX)>100){
    var fY = distanceY> 0 ? -350: 0;
    this.body.ApplyForce( new b2.Vec2(sign * -50,fY),this.body.GetPosition() );
    if(distanceX>0){this.flip = true;}
    else {this.flip = false;}
    if (Math.random() > 0.9){
      var x = this.pos.x + (this.flip ? -6 : 6 );
      var y = this.pos.y + 6;
      ig.game.spawnEntity( EntityBossbullet, x, y,{flip:this.flip} );
    }
    if(distanceY>= 0){this.currentAnim = this.anims.fly;}
    else{this.currentAnim = this.anims.idle;}
  }
  else if (Math.abs(distanceX) <= 100){
    if(Math.random() > 0.9){
      var x = this.pos.x + (this.flip ? -6 : 6 );
      var y = this.pos.y + 6;
      ig.game.spawnEntity( EntityBossbullet, x, y,{flip:this.flip} );
    }
  }
  this.body.SetXForm(this.body.GetPosition(), 0);
  if (distanceX> 0){this.currentAnim.flip.x = true;}
  else{this.currentAnim.flip.x = false;}
  this.cooldowncounter ++;
  this.parent();
}
```

1.  boss 实体的`update()`函数与其他实体有三个主要区别：

+   由于他是一个更大的生物，他需要更多的力量来移动。

+   我们希望他用子弹造成伤害，这样他就不会试图进入近战范围。当他在 x 轴上的距离为 1000 像素时，他会接近。一旦距离为 100 像素，他就不会再靠近了。

+   最后但并非最不重要的是，在每一帧中，他有 1/10 的几率发射一颗子弹。这平均每秒应该会导致 6 颗子弹，这是相当密集的火力。如果你非常不幸，他可以在一秒内向你发射多达 60 颗子弹。

Box2D 碰撞的一个相当好的效果是，作为玩家，你自己的子弹可以偏转 boss 的子弹。然而，这并不总是这样。Box2D 中的碰撞检测还不完美，有时两个实体可以直接穿过彼此。这也是为什么你应该确保你的外边界碰撞墙非常厚。否则，你的实体可能会飞出你的关卡，可能导致游戏崩溃。

![最终战斗](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_4_14.jpg)

击败 boss 角色应该结束游戏，并给玩家一个漂亮的胜利画面。死亡应该以游戏结束画面而不是游戏崩溃画面结束。这些以及许多其他事情将在第五章中得到解决，*为您的游戏添加一些高级功能*，在那里我们将更深入地研究一些更高级的功能，以增强您的游戏。

当游戏接近尾声时，玩家期望有一个高潮。这可以通过与一个值得的敌人进行一场史诗般的战斗来给他。这正是我们在本章早些时候所做的。boss 角色是玩家的终极敌人，也是他取得胜利的关键：

+   打开一个新文件并将其保存为`boss.js`。

+   将 boss 角色的基本功能作为敌人实体的扩展。

+   引入 boss 的子弹，也就是 boss 用来杀死玩家的抛射物。这是玩家自己使用的抛射物的扩展。

+   升级 boss，使他能够利用他的致命新子弹。

+   在游戏中添加一个 boss 并查看你是否能击败他。

# 总结

在本章中，我们了解了横向卷轴游戏，并看了一些著名的例子。我们使用了集成了 ImpactJS 的物理引擎 Box2D 构建了自己的横向卷轴游戏。

首先，我们使用 Weltmeister 建立了一个关卡，这样我们就可以用我们新创建的敌人和可玩角色来填充它们。我们添加了无生命的箱子，以完全展示 Box2D 的物理效果。为了武装玩家对抗暴力敌人，我们引入了拾取物品和两种有趣的武器，即子弹和炸弹。

我们的敌人在我们添加了轻微的人工智能后获得了生命。作为玩家的最终挑战，强大的 boss 被带到了场景中。这个敌人比普通敌人更强大，能够像玩家一样发射子弹。为了击败每个敌人，玩家将获得额外的积分。

在下一章中，我们将探讨一些新概念，比如处理数据，并深入一些我们已经接触过的功能，比如调试人工智能。


# 第五章：为您的游戏添加一些高级功能

在之前的章节中，我们看到了如何设置工作环境，看了 Impact 引擎，甚至构建了两种类型的游戏。现在是时候看一些有趣的额外内容了。

为了测试本章涵盖的元素，最好要么下载`第五章`文件夹中的代码材料，要么直接在我们设计的游戏中构建第三章中的游戏，*让我们建立一个角色扮演游戏*。由于本章我们不会使用 Box2D 扩展，一些东西将与第四章中的侧面卷轴游戏不兼容，*让我们建立一个侧面卷轴游戏*。在本章中，我们将涵盖：

+   制作开始和胜利画面

+   额外的调试可能性和引入定制的 ImpactJS 调试面板

+   使用 cookie 和 lawnchair 应用程序保存数据，并将 Excel 文件转换为有用的游戏数据

+   在第三章的角色扮演游戏（RPG）中的一些额外游戏功能，*让我们建立一个角色扮演游戏*

+   通过鼠标移动角色

+   智能生成位置

+   添加基本对话

+   显示玩家的生命值条

+   通过集体智慧扩展人工智能（AI）

+   实施 Playtomic 进行游戏分析

# 开始和游戏结束画面

当玩家开始游戏时，你可能希望他看到的第一件事是一个闪屏。这个屏幕通常包含游戏的名称和其他有趣的信息；通常包含一些关于游戏故事或控制的信息。在游戏结束时，你可以有一个胜利画面，告诉玩家他在排行榜上的得分有多高。

在代码方面，可以通过在实际游戏旁边引入新的游戏实例来实现。每个屏幕：开始、游戏结束和胜利都是 ImpactJS 游戏类的直接扩展。让我们首先创建一个开始画面。

## 游戏的开始画面

为了制作一个漂亮的开场画面，我们需要一个背景图片和我们信任的`main.js`脚本：

1.  打开`main.js`脚本并插入以下代码：

```js
OpenScreen = ig.Game.extend({
  StartImage : new ig.Image('media/StartScreen.png'),
  init:function(){
  if(ig.ua.mobile){
    ig.system.setGame(MyGame);
  }
    ig.input.bind(ig.KEY.SPACE,'LoadGame');
  },
  init:function(){
    if(ig.ua.mobile){ig.input.bindTouch( '#canvas','LoadGame' );}
    else {ig.input.bind(ig.KEY.SPACE,'LoadGame');}
  },
```

1.  开场画面是`ig.Game`函数的扩展，就像我们的游戏一样。事实上，当我们完成这里的工作后，我们将有四个游戏实例：一个真正的游戏称为`MyGame`，另外三个游戏，它们只是作为开始、胜利或游戏结束画面。这可能有点反直觉，因为你可能期望这些画面是同一个游戏的一部分。实际上，这绝对是真的。然而，在代码中，将这些画面转换为单独的游戏类扩展更方便。

1.  在`OpenScreen`代码的这一部分中，我们首先定义了我们将要显示的图像：`StartScreen.png`。

1.  最后，我们将空格键绑定到一个名为`LoadGame`的动作状态，如下所示：

```js
  update:function(){
    if(ig.input.pressed('LoadGame')){
      ig.system.setGame(MyGame);
    }
  },
```

1.  现在我们可以通过按空格键加载游戏，但我们仍然需要在屏幕上实际显示一些东西。

1.  我们可以通过操纵任何 ImpactJS 类的`draw()`函数来可视化事物，如下面的代码片段所示：

```js
  draw: function(){
    this.parent();
    this.StartImage.draw(0,0);
    var canvas = document.getElementById('canvas');
    if(canvas.getContext){
      var context = canvas.getContext('2d');
      context.fillStyle = "rgb(150,29,28)";
      context.fillRect (10,10,100,30);
    }
    var font = new ig.Font('media/font.png');
    font.draw('player:' + GameInfo.name,10,10);
  }
}),
```

1.  `draw()`函数将绘制我们在初始化`OpenScreen`函数时指定的背景图像。这样做后，它还会添加一个小的红色矩形，我们将在其中打印玩家的名字（如果有的话）。我们将在本章后面查看游戏数据时，获取这个名字并存储它以供以后使用。目前，`GameInfo.name`变量是未定义的，将会像开始新游戏一样显示出来。

1.  为了确保我们全新的开场画面实际上被使用，我们需要在我们的`ig.main`函数调用中用`OpenScreen`函数替换`MyGame`游戏类实例，如下面的代码行所示：

```js
ig.main( '#canvas', OpenScreen, 60, 320, 240, 2 );
```

现在我们有了一个开场画面！添加游戏结束画面和胜利画面的过程非常相似。在制作这些其他画面之前，让我们快速回顾一下我们刚刚做的事情：

+   我们确保`media`文件夹中有背景图像

+   我们添加了`OpenScreen`函数作为一个新的游戏实例

+   我们绑定了空格键，以便用来加载实际游戏

+   我们设置了`Draw()`函数，以便它可以显示背景，甚至以后还可以显示玩家的名字

+   我们在`OpenScreen`函数窗口中初始化了我们的画布，而不是在`MyGame`游戏类实例中

## 胜利和游戏结束画面

胜利画面是游戏实体的一个相对简单的扩展。对于我们想要显示的每种类型的画面，该过程几乎是相同的。要设置胜利画面，请按照以下步骤进行：

1.  打开`game.js`文件，并添加我们的新`GameEnd`游戏类，如下所示：

```js
GameEnd = ig.Game.extend({
  EndImage : new ig.Image('media/Winner.png'),

  init:function(){
    if(ig.ua.mobile){ig.input.bindTouch( '#canvas','LoadGame' );}
    else {ig.input.bind(ig.KEY.SPACE,'LoadGame');}
  },
```

1.  我们需要初始化的是我们将要显示的图像和一个用于重新开始游戏的键。

1.  与开始画面类似，我们使用空格键加载新游戏。我们通过在`update`函数中添加以下`if`语句来不断检查空格键是否被按下：

```js
  update:function(){
    if(ig.input.pressed('LoadGame')){
      ig.system.setGame(MyGame);
    }
  },
```

1.  我们需要使用以下代码绘制实际的游戏结束图像，并放置文本**HIT SPACE TO RESTART**。这样我们就确保玩家不会刷新浏览器而是使用空格键。

```js
  draw: function(){
    this.parent();
    var font = new ig.Font('media/font.png');
    this.StartImage.draw(0,0);

  if(ig.ua.mobile){
    font.draw('HIT THE SCREEN TO RESTART:',100,100);
  }
else font.draw('HIT SPACE TO RESTART:',100,100);
  }
}),
```

1.  当玩家到达游戏结束时，需要显示胜利画面。在我们的情况下，这将是当 boss 实体被击败时。打开`boss.js`文件，并按照以下代码更改`kill()`方法，以便在他死亡时加载胜利画面：

```js
kill: function(){
  ig.game.gameWon();
}
```

1.  在`kill()`方法中，我们调用了`gameWon()`函数，这是我们当前游戏的一个方法，但尚未定义。

1.  打开`game.js`文件，并将`gameWon()`方法添加为`MyGame`文件的一个新方法，如下所示。

```js
gameWon: function(){
  ig.system.setGame(GameEnd);
}
```

1.  目前，引入一个额外的中间函数来调用胜利画面可能看起来有点无聊。然而，一旦我们开始处理游戏数据，这将开始变得有意义。最终，这个函数不仅会调用胜利画面，还会保存玩家的得分。使用中间函数比直接将`ig.system.setGame()`函数添加到玩家实体中是一种更干净的编程方式。

### 注意

游戏结束画面可以是胜利画面的确切等价物，只是使用另一张图像，并且是由玩家的死亡而不是 boss 的触发。

1.  如下所示，在`game.js`文件中添加`gameOver`函数：

```js
gameOver = ig.Game.extend({
  gameOverImage : new ig.Image('media/GameOver.png'),
  init: function(){
    ig.input.bind(ig.KEY.SPACE,'LoadGame');
  },
  update:function(){
    if(ig.input.pressed('LoadGame')){
      ig.system.setGame(MyGame);
    }
  },
  draw: function(){
    this.parent();
    var font = new ig.Font('media/font.png');
    this.gameOverImage.draw(0,0);
    font.draw('HIT SPACE TO RESTART',150,50);
  }
}),
```

1.  通过使用以下代码调整他的`kill()`方法，确保`gameOver`函数在玩家死亡时被触发：

```js
kill: function(){
    ig.game.gameOver();
}
```

1.  再次调用中间函数来处理实际画面加载。这个函数需要作为`MyGame`游戏类实例的一个方法添加。

1.  在`game.js`脚本中，将`gameOver()`方法添加到`MyGame`游戏类实例中，如下所示：

```js
gameOver: function(){
  ig.system.setGame(gameOver);
},
```

这些都是非常基本的开始和游戏结束画面，它们表明可以通过使用`ig.game`类作为起点来完成。对于胜利和游戏结束画面，一个好主意是显示排行榜或在游戏过程中收集的其他有趣信息。

当游戏通过添加高级功能变得更加复杂时，调试变得越来越重要，以应对这些增加的复杂性。我们现在将看看我们可以使用哪些高级调试选项。然而，在我们这样做之前，让我们快速回顾一下胜利和游戏结束画面：

+   我们制作了两个新的游戏实例，作为胜利和游戏结束画面

+   `update`函数被调整以监听空格键，而`draw`函数被调整以显示背景图像和**HIT SPACE TO RESTART**消息

+   老板和玩家实体的功能被调整以触发胜利和游戏结束屏幕

+   我们使用了名为`gameOver()`和`gameWon()`的中间函数，因为我们希望稍后调整它们，以便触发 lawnchair 应用程序来存储分数

## 更高级的调试选项

在第一章中，*启动你的第一个 Impact 游戏*，我们看了如何使用浏览器进行调试以及 ImpactJS 调试面板提供了什么。在这里，我们将进一步制作一个新的 ImpactJS 调试面板。这段代码由 Dominic 在他的 ImpactJS 网站上提供，但很多人忽视了这个功能，尽管它非常有用。

在第一章中，*启动你的第一个 Impact 游戏*，我们还谈到了逻辑错误，这是一种非常难以找到的错误，因为它不一定会在浏览器调试控制台中生成错误。为了应对这些错误，程序员经常使用一种称为单元测试的方法。基本上，这涉及到预先定义每段代码的期望结果，将这些期望结果转化为条件，并测试输出是否符合这些条件。让我们看一个简短的例子。

## 单元测试的简短介绍

我们的 ImpactJS 脚本中最基本的组件之一是函数。我们的一些函数返回值，其他函数直接改变属性。假设我们有一个名为`dummyUnitTest()`的函数，它接受一个参数：`functioninput`。

```js
dummyUnitTest: function(inputnumber){
  var outputnumber= Math.pow(inputnumber,2);
  return null; // can cause an error in subsequentfunctions,comment out to fix it
  return outputnumber;
}
```

`inputnumber`变量可以是任何数字，但我们的函数将`inputnumber`变量转换为`outputnumber`变量，然后返回它。`inputnumber`变量的平方应该始终返回一个正数。所以我们至少可以说两件事关于我们对这个函数的期望：输出不能为 null，也不能为负数。

我们可以通过添加专门用于检查特定条件的`assert`函数来对这个函数进行单元测试。`assert`函数检查一个条件，当条件为假时，它会将消息写入控制台日志。控制台元素本身具有这个函数，当调试模块被激活时，ImpactJS 也有这个函数。`ig.assert()`函数是`Console.assert()`函数的 ImpactJS 等价物。记住，通过在`main.js`文件中包含`'impact.debug.debug'`来激活 ImpactJS 调试。使用`ig.assert`函数优于`console.assert()`函数。这是因为在准备启动游戏时，通过简单地关闭 ImpactJS 调试模块来摆脱`ig`类消息。控制台类的方法，如`console.assert()`调用需要单独关闭。一般来说，`assert()`函数看起来像这样：

```js
ig.assert(this.dummyUnitTest('expected')==='expected','you introduced a logical error you should retrieve the same value as the input');
```

对于我们的具体示例，我们可以执行几个测试，如下所示的代码：

```js
ig.assert(typeof argument1 === 'number','the input is not a number');
ig.assert(typeof argument2 === 'number','the output is not a number');
ig.assert(typeof argument2 >= 0,'the output is negative');
ig.assert(typeof argument2 != null,'the output is null);
```

我们可以继续，这种方法并不是没有过度的缺陷。但一般来说，当你计划构建一个非常复杂的游戏时，单元测试可以通过减少你寻找逻辑错误源的时间来极大地帮助你。例如，在这种情况下，如果我们的输出是一个负数，函数本身不会失败；也许大部分依赖于这个函数的代码也不会失败，但在链条的某个地方，会有问题。在引入所有这些依赖关系的同时，一个函数建立在另一个函数之上，依此类推，单元测试是完全合理的。

在`ig.assert()`和`ig.log()`函数旁边还有另一个有趣的函数。它是`console.log()`函数的 ImpactJS 等价物，将始终写入日志，而不检查特定条件。这对于在不必在**文档对象模型**（**DOM**）中寻找的情况下关注敌人的健康状况非常有用。

让我们在继续使用我们自己的 ImpactJS 调试面板之前，快速回顾一下单元测试的内容：

+   单元测试是关于预见您期望代码组件执行的操作，并返回和检查输出的有效性。

+   我们使用`ig.assert()`或`console.assert()`函数来检查某些条件，并在违反条件时向日志打印消息。

## 将您自己的调试面板添加到 ImpactJS 调试器

如前所述，通过简单地在`main.js`文件中包含`'impact.debug'`语句来激活调试面板。开始新游戏时，面板会最小化显示在屏幕底部，只需点击即可完全显示。

让我们开始构建我们自己的面板，这将使我们能够在玩游戏时激活和停用实体。这样我们就可以在游戏中毫无阻碍地通过最凶猛的敌人，通过冻结它们的位置。让我们开始吧：

1.  打开一个新文件，将其保存为`MyDebugPanel.js`。

1.  在文件中插入以下代码：

```js
ig.module(
  'plugins.debug.MyDebugPanel'
)
.requires(
  'impact.debug.menu',
  'impact.entity',
  'impact.game'
)
.defines(function(){
ig.Game.inject({
  loadLevel: function( data ) {
    this.parent(data);
    ig.debug.panels.fancypanel.load(this);
  }
})
})
```

1.  在我们实际定义面板之前，我们将在两个 ImpactJS 核心类中注入代码：`Game`和`Entity`。注入代码就像扩展一样，只是我们不创建一个新类。原始代码被其扩展版本所替换。在前面的代码中，我们告诉核心`loadlevel()`函数也要加载我们的面板，这将被称为**Fancy panel**。

1.  然后，通过在核心实体代码中添加一个新属性`_shouldUpdate`来升级，如下所示：

```js
ig.Entity.inject({
  _shouldUpdate: true,update: function() {if( this._shouldUpdate ) {this.parent();}
  }
});
```

1.  当为 true 时，实体的`update`方法将被调用，这也是默认方法。但是，当为 false 时，`update()`函数将被绕过，并且实体不会执行任何实际操作。

1.  现在让我们来看看面板本身。我们可以看到面板中包含以下代码：

```js
MyFancyDebugPanel = ig.DebugPanel.extend({
  init: function( name, label ) {
    this.parent( name, label ); 
    this.container.innerHTML = '<em>Entities not loadedyet.</em>';
  },
}
```

1.  我们的花哨面板被初始化为 ImpactJS 面板的扩展，称为`DebugPanel`。调用`this.parent`函数将确保向面板提供一个 DIV 容器，以便它可以在 HTML5 中显示。如果游戏中没有实体，容器将不包含任何内容，因此会放置一条消息。例如，这将是我们的开始和结束屏幕的情况。由于`this.container.innerHTML`函数将保存面板的内容，因此在开始屏幕中打开面板应该会显示消息**Entities not loaded yet**。

为了显示先前的消息，我们应该在`this.container.innerHTML`函数中添加以下代码：

```js
load: function( game ) {
  this.container.innerHTML = '';
    for( var i = 0; i < game.entities.length; i++ ) {
      var ent = game.entities[i];
      if( ent.name ) {
        var opt = new ig.DebugOption( 'Entity ' + ent.name, ent,'_shouldUpdate' );
        this.addOption( opt );
        this.container.appendChild(document.createTextNode('health: '+ ent.name + ' :' +ent.health));
      }
    }
},
```

1.  在加载级别时，我们的面板将填充游戏中的所有实体，并提供关闭它们的`update()`函数的选项。还会显示它们的健康状况。`addOption()`函数使得可以在需要时从 true 切换到 false，并反之。它接受两个参数：一个标签和需要在 true 和 false 之间交替的变量。

1.  这些最后的函数并没有用于我们特定的面板，但仍然很有用。以下代码解释了先前的函数：

```js
ready: function() {
  // This function is automatically called when a new gameis created.
  // ig.game is valid here!
},
beforeRun: function() {
  // This function is automatically called BEFORE eachframe is processed.
},
afterRun: function() {
  // This function is automatically called AFTER each frameis processed.
}
});
```

1.  `load()`、`ready()`、`beforeRun()`和`afterRun()`函数之间的主要区别在于它们在游戏中被调用的时刻。根据您的需求，您将使用一个，另一个或者组合。我们使用了`load()`方法，它在加载级别时被调用。但对于其他面板，您可能希望使用其他方法。

1.  最后一步，我们实际上将定制面板添加到我们的标准面板集中，如下所示：

```js
ig.debug.addPanel({
  type: MyFancyDebugPanel,
  name: 'fancypanel',
  label: 'Fancy Panel'
});
```

1.  重新加载游戏，看看您的新面板。尝试冻结您的敌人！您会注意到敌人仍然会面对玩家，但不会朝向他移动。这是因为我们禁用了它们的`update()`方法，但没有禁用它们的`draw()`方法。

现在我们将继续使用游戏数据，但让我们首先看一下我们刚刚涵盖的内容：

+   ImpactJS 有一个非常有趣的调试器，您可以设计自己的面板。

+   通过在主脚本中包含`'impact.debug.debug'`命令来激活 ImpactJS 调试器。

+   我们通过扩展 ImpactJS 的`DebugPanel`类制作了自己的面板。我们自己的面板需要让我们能够将任何实体冻结在位置上，这样我们就可以无阻碍地探索我们的关卡。

+   利用一种称为注入的技术；我们改变了我们的核心实体类，以便调试面板可以控制每个实体的`update`函数。

+   最后，我们将我们的调试面板添加到标准设置中，以便随时可用。

# 处理游戏数据

处理数据对于游戏构建可能是至关重要的。简单的游戏不需要显式的数据管理。然而，当我们开始研究那些包含对话或保持高分的游戏时，理解数据处理就成为一个重要的话题。我们将讨论两件事：

+   将数据引入游戏

+   存储在游戏中生成的数据

对于后者，我们将看看解决问题的两种不同方式：cookie 和 lawnchair 应用程序。

首先让我们看看如果我们想要在 NPC 和玩家之间的对话中引入数据，我们需要做些什么。

## 向游戏添加数据

如前所述，RPG 游戏通常充满了玩家和多个非玩家角色（NPC）之间的对话。在这些对话中，玩家在回答时会有几个选项。这方面的代码机制可能会变得非常复杂，我们将在本章后面详细介绍，但首先我们需要实际的句子。我们可以在诸如 Excel 之类的应用程序中准备这些句子。

![向游戏添加数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_3.jpg)

设置 RPG 对话是一门艺术；有许多方法可以做到这一点，每种方法都有其优缺点。创建一个体面的对话设置和流程，甚至是数据库方面的，是一个超出本书范围的讨论。在这里，我们将尽量简单，并与两个表一起工作：一个用于 NPC 可以说的所有事情，另一个用于玩家可以回答的事情。我们游戏中对话的流程将如下：

1.  NPC 说了些什么。NPC 可以说的一切都有一个名为**NPC_CONVO_KEY**的唯一键。

1.  玩家将被呈现一组可能的答案。每组都有一个名为**REPLY_SET_KEY**的键。除此之外，虽然我们不会使用它，但每个答案都有自己的唯一键，我们称之为**UNIQUE_REPLY_KEY**。即使你现在不使用它们，拥有主键也是一个很好的做法。

1.  玩家选择其中一个答案。答案有一个外键，指向 NPC。我们将这个外键命名为**NPC_CONVO_KEY**。

1.  使用**NPC_CONVO_KEY**，NPC 知道接下来该说什么，我们已经完成了循环。这将继续进行，直到对话被突然中止或自然结束。

实际的句子保存在变量**PC_SPEECH**和**NPC_SPEECH**中。

我们可以在 Excel 文档中轻松准备我们的数据，但我们仍需要将其导入到我们的游戏中。我们将使用转换器，例如以下网站上的转换器：[`shancarter.com/data_converter/`](http://shancarter.com/data_converter/)。

只需将数据从 Excel 复制粘贴到转换器中，并选择**JSON-Column Arrays**，即可将数据转换为 JSON 格式文档。

一旦以这种格式存在，我们所需要做的就是将数据复制粘贴到单独的模块中。以下代码是我们的 Excel 数据转换为 JSON 后的样子：

```js
ig.module('plugins.conversation.npc_con')
.defines(function(){
npc_con=/*JSON[*/{
  "NPC_CONVO_KEY":[1,2,3,4,5,6,7],
  "NPC_SPEECH":["Hi, are you allright?","That is great! Bye now!","Ow, why? What is wrong?","You are mean!","Ow. You should see the doctor, he lives in the green house a bitfurther. Good luck!","Please explain. Maybe I can help you?","Bye!"],
  "REPLY_SET_KEY":[1,0,3,0,0,6,0]
}
});
```

我们将数据以 JSON 格式存储，就像 Weltmeister 对级别文件所做的那样。以下代码是玩家的语音数据转换为 JSON 后的样子：

```js
ig.module( 'plugins.conversation.pc_con' )
.defines(function(){
pc_con=/*JSON[*/{
  "UNIQUE_REPLY_KEY":[1,2,3,4,5,6,7,8],
  "REPLY_SET_KEY":[1,1,1,3,3,3,6,6],
  "PC_SPEECH":["Yes","No","Go away","I am sick","I am sick of you","You know, stuff.","I will be fine! Bye!","Get lost! "],
  "NPC_CONVO_KEY":[2,3,4,5,4,6,7,4]
}
});
```

现在剩下的就是将数据放入我们的游戏目录，并在`main.js`文件中包含这两个文件：

```js
'plugins.conversation.npc_con',
'plugins.conversation.pc_con',
```

如果您重新加载游戏，您应该能够在 Firebug 应用程序中探索您新引入的数据，如下面的屏幕截图所示：

![向游戏添加数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_4.jpg)![向游戏添加数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_5.jpg)

现在我们已经看了如何引入数据，让我们来看一下两种在玩家计算机上存储数据的方法，首先是使用 cookie。但首先让我们总结一下我们在这里所做的事情：

+   设置对话是一门艺术，本章不会深入探讨

+   我们在 Excel 或等效应用程序中设置了一个简单的对话

+   这个 Excel 表格被转换为 JSON 格式的文档。您可以使用在线转换器来做到这一点，比如[`shancarter.com/data_converter/`](http://shancarter.com/data_converter/)

+   我们将新的 JSON 编码数据转换为 ImpactJS 模块

+   最后，我们在我们的主脚本中包含了这两个新创建的数据模块

## 使用 cookie 在玩家的计算机上存储数据

Cookie 不过是存储在浏览器中的一段字符串数据，许多网站用它来跟踪访问者。如果您使用 Google Analytics，您可能知道 Google 提供了一个脚本，为每个访问者放置了几个不同的 cookie。Google Analytics 并不是唯一以这种方式工作的程序。在一天愉快的上网之后，您的浏览器中充满了 cookie；其中一些将在几个月内保留，直到最终删除自己。

在用户的浏览器中存储玩家姓名和最高分等信息是有意义的；您不需要从您这边进行存储，因此不需要 PHP 或 SQL 编码。缺点是如果玩家决定清理浏览器，数据将丢失。此外，在使用 cookie 时与玩家之间没有真正的一对一关系。一个人可以有多个设备，甚至每个设备可以有多个浏览器。因此，建议对您总是从头开始重玩的游戏使用 cookie。对于需要玩家大量时间投入的游戏来说，这显然不适用；例如，大型多人在线角色扮演游戏（MMORPGs）往往是如此。对于这些更高级的游戏，使用帐户和服务器端数据库是正确的方式。

让我们按照以下步骤构建一个能够存储玩家姓名的 cookie 插件，这样我们可以在重新开始游戏时检索它：

1.  打开一个新文件，将其保存为`cookie.js`。插入基本的类扩展代码如下：

```js
ig.module('plugins.data.cookie').
  defines(function(){
    ig.cookie = ig.Class.extend({
    userName : null,
    init: function(){
      this.checkCookie();
  },
```

1.  我们首先将我们的 cookie 插件定义为 ImpactJS 类扩展。我们知道它以后将需要存储用户名，所以让我们用值`null`来初始化它。我们的新 DOM 对象创建时，第一件事就是调用`checkCookie()`函数。`checkCookie()`函数将检查是否已经存在存储了相同用户名的 cookie。当然这里有两种可能性：存在或不存在。如果不存在，需要提示并存储名称。如果用户名以前已存储，可以检索出来。

1.  将 cookie 放置在位置上是使用`setCookie()`函数完成的，如下面的代码所示：

```js
setCookie: function(c_name,value,exdays){
  var exdate=new Date();
  exdate.setDate(exdate.getDate() + exdays);
  var c_value=escape(value) + ((exdays==null) ? "" : ";expires="+exdate.toUTCString());
document.cookie=c_name + "=" + c_value;
},
```

1.  这个函数接受三个参数：

+   `c_name`：它需要存储的变量的名称，即用户名

+   `value`：用户名的值

+   `exdays`：cookie 允许存在的天数，直到它应该从浏览器中删除自己

1.  `setcookie()`函数用于检查输入数据的有效性。该值被转换，因此业余黑客更难插入有害代码而不是名称。然后将数据存储在`document.cookie`变量中，这是 DOM 的一部分，它存储所有 cookie，并在关闭页面时不会丢失。深入研究`document.cookie`变量的工作方式将使我们走得太远，但它的行为非常奇特。如前面的代码片段所示，将值分配给`document.cookie`变量不会用新分配的值替换已经存在的值。相反，它将添加到堆栈的其余部分。

1.  如果有`setCookie()`函数，当然也有`getCookie()`函数，如下面的代码片段所示：

```js
getCookie: function(c_name){
  var i,x,y,ARRcookies=document.cookie.split(";");
  for (i=0;i<ARRcookies.length;i++){
    x=ARRcookies[i].substr(0,ARRcookies[i].indexOf("="));
    y=ARRcookies[i].substr(ARRcookies[i].indexOf("=")+1);
    x=x.replace(/^\s+|\s+$/g,"");
    if (x==c_name){
      return unescape(y);
    }
  }
},
```

1.  前面的代码将解码转换后的 cookie 并返回它。它的唯一输入参数是您要查找的变量的名称。

1.  在编程中，特别是在 Java 中，很常见使用`set`和`get`函数的组合来更改属性。因此，根据这种编程逻辑，例如`health`属性应该始终具有`setHealth()`和`getHealth()`函数。直接更改参数有优点和缺点。直接更改属性的主要优点是实用主义；事情保持简单和直观。一个很大的缺点是维护代码的有效性的挑战。如果任何地方都可以随意更改任何实体的任何属性，如果失去了对事物的视野，就会出现严重问题。

1.  `checkCookie()`函数通过使用`getCookie()`函数检查浏览器中是否存在用户名：

```js
checkCookie :function(){
  var username=this.getCookie("username");
  if (username!=null && username!=""){
  this.setUserName(username);
  }
  else {
    username=prompt("Please enter your name:","");
    if (username!=null && username!=""){
      this.setCookie("username",username,365);
    }
  }
},
```

1.  如果存在 cookie，则使用获取的用户名作为输入参数调用`setUserName()`函数。如果没有 cookie，则提示玩家插入他/她的名字，然后使用`setCookie()`函数存储。

1.  `getUserName()`和`setUserName()`函数在本示例中保持相对基本，如下面的代码所示：

```js
getUserName: function(){
  return this.userName;
},
setUserName: function(userName){
  if(userName.length > 10){alert("username is too long");}
  else { this.userName = userName; }
}
```

1.  `setUsername()`和`getUsername()`函数可以通过直接使用`checkCookie()`和`setCookie()`函数来获取或设置`this.username`命令来省略。然而，正如前面所说的，使用`set`和`get`语句是一种良好的编程实践，无论何时需要更改属性。正如在`setUserName()`函数中所看到的，这些函数可以内置一些额外的检查。虽然`getCookie()`和`setCookie()`函数确保数据以无害的方式存储和适当获取，但`setUserName()`和`getUserName()`函数可以用于检查其他约束，例如名称长度。

1.  现在我们已经完成了我们的 cookie 扩展，我们实际上可以利用它。打开`main.js`文件，并将以下两行添加到`GameInfo`类中：

```js
this.cookie = new ig.cookie();//ask username or retrieve ifnot set
this.userName = this.cookie.getUserName();//store theusername
```

1.  `GameInfo`类非常适合这个；我们希望在游戏实例之外保持可用的所有内容都需要在`GameInfo`类中收集。尽可能将数据组件与游戏逻辑分离是保持代码清晰和易于理解的一种方式，当游戏变得更加复杂时。

1.  我们的第一行代码将创建一个`ig.cookie`数组，并立即检查用户名是否存在。如果不存在，将出现提示，并在玩家填写提示警报后存储该名称。

1.  第二行简单地将用户名传递给我们在第三章中首次遇到的`GameInfo`对象，*让我们建立一个角色扮演游戏*。您可能还记得，我们在本章的开头使用了`GameInfo.name`变量，但它是未定义的。现在它将被设置为`null`，直到玩家给出他的名字，并且以后用于他玩的每个游戏。![使用 cookie 在玩家的计算机上存储数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_6.jpg)

最初，玩家的名字将是未知的，并且在屏幕上将显示**null**，如前一个截图所示。

![使用 cookie 在玩家的计算机上存储数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_7.jpg)

然而，玩家被提示在窗口中填写他或她的名字，如前一个截图所示。

![使用 cookie 在玩家的计算机上存储数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_8.jpg)

因此，真实姓名将如前一个截图所示地显示在屏幕上。

虽然您应该能够绕过使用 cookie，但还有另一种存储数据的方式，可能更多功能和易于使用：lawnchair。lawnchair 应用程序利用 HTML5 本地存储，也称为 DOM 存储。在转向 lawnchair 应用程序之前，我们将快速了解如何在不使用 lawnchair 应用程序的情况下使用 HTML5 本地存储：

+   Cookie 是一种在玩家浏览器中存储数据的方式。许多网站使用它们，包括网络分析平台 Google Analytics。Cookie 对于短时间内反复玩的游戏很有用，而不适用于需要长时间存储许多东西的复杂游戏。

+   我们可以通过创建一个`cookies`插件来实现使用 cookie。一旦激活了这个插件，它将检查是否已经存在 cookie，如果没有找到，则放置一个。

+   在这个例子中，我们使用 cookie 来存储和检索玩家的名字，如果没有 cookie，我们首先要求他填写。

+   重点放在使用`set()`和`get()`函数上。这些函数是 Java 中的标准做法，是一种有用的技术，可以在代码中保持对事物的视野，并检查任何属性的有效性，即使代码变得更加复杂。

## 本地存储

本地存储，也称为 DOM 存储，是 HTML5 的一个功能，允许您在用户的计算机上保存信息。它几乎在所有方面都优于 cookie，但是旧版浏览器不支持它。使用本地存储相当简单，如下面的代码片段所示：

```js
ig.module('plugins.data.local').
defines(function(){
  ig.local = ig.Class.extend({
    setData: function(key, data){
      localStorage.setItem(key, data);
    },
    getData: function(key){ 
      return localStorage.getItem(key);
    }
  });
})
```

这个插件并不是必需的，以便使用本地存储。它只是一个扩展，使用`get`和`set`技术来检查数据的有效性。您可以通过在`main.js`脚本中包含`'plugins.data.local'`命令并调用`setData()`和`getData()`函数来使用该插件。

```js
Ls = new ig.local(); //localstorage
  Ls.setData("name","Davy");
  alert(Ls.getData("name"));
```

现在我们来快速看一下如何一般使用本地存储；让我们看看 lawnchair 应用程序提供了什么。

## 使用 lawnchair 作为存储数据的多功能方式

lawnchair 应用程序是在客户端存储数据的免费且非常专业的解决方案。它能够以多种方式存储数据，并且 ImpactJS 的插件已经准备就绪。让我们看看如何使用 lawnchair 应用程序来存储数据：

1.  从以下网站下载 lawnchair 应用程序：[`brian.io/lawnchair/`](http://brian.io/lawnchair/)，或者您可以在[`github.com/jmo84/Lawnchair-plugin-for-ImpactJS`](https://github.com/jmo84/Lawnchair-plugin-for-ImpactJS)上下载适用于 ImpactJS 的版本。

1.  将文件放入您的`plugin`文件夹中。在这个例子中，它们被放在名为`data`和`Lawnchair`的单独子文件夹中。但是，只要确保相应地更改代码，您可以自由使用任何结构。

1.  在您的`main.js`文件中包含`impact-plugin`文件，如下面的代码所示：

```js
'plugins.data.lawnchair.impact-plugin',
```

1.  通过使用新获得的`ig.Lawnchair()`方法，将存储元素添加到您的`GameInfo`类中，如下面的代码行所示：

```js
this.store = new ig.Lawnchair({adaptor:'dom',table:'allscores'},function() { ig.log('teststore is ready'); }),
```

`ig.Lawnchair()`方法接受两个输入参数：

+   第一个参数是最重要的，实际上是一个数组。在这个数组中，您需要指定两件事情：您想要使用哪种方法来存储所有内容，以及您想要创建的数据存储的名称。第一个变量称为`adaptor`，因为 lawnchair 应用程序使用适配器模式技术来决定接下来需要发生什么。lawnchair 应用程序编程非常高效，通过使用模式立即变得明显。适配器模式本质上是一段代码，将您自己的代码链接到 lawnchair 应用程序的存储系统。没有这种模式，要与实际的 lawnchair 应用程序源代码进行通信将会非常困难。在这里，我们选择将其保存为永久 DOM 存储，但也可以选择其他选项，如 Webkit-SQLite。

### 注意

Webkit-SQLite 与永久 DOM 存储不同，它更像是一个常规数据库，但是在客户端的本地存储上运行。例如，像其他数据库一样，您可以使用 SQL 查询 Webkit-SQLite 存储。

+   第二个输入参数是可选的。在这里，您可以放入需要在准备好`store`变量时执行的函数。这是放置日志消息的完美位置。

1.  现在我们的存储元素已经准备就绪，只需调用`store.save()`方法存储任何您想要的数据。假设我们想要存储玩家的分数。为此，我们可以向`GameInfo`类添加一个执行相同操作的方法。

```js
this.saveScore = function(){
  this.store.save({score:this.score});
}
```

1.  `saveScore()`函数可以添加到我们构建胜利和游戏结束屏幕时创建的`gameOver()`和`gameWon()`方法中，如下所示：

```js
gameOver: function(){
 GameInfo.saveScore();
  ig.system.setGame(gameOver); 
},
gameWon: function(){
 GameInfo.saveScore();
  ig.system.setGame(GameEnd); 
}
```

1.  当玩家死亡或赢得比赛时，他的分数将使用 lawnchair 永久 DOM 方法保存。永久 DOM 并不意味着 DOM 永久保存在用户的 PC 上；这只是本地存储的另一个名称。

1.  我们需要能够做的最后一件重要的事情是检索数据。为此，我们向`GameInfo`类引入了三个新函数：

+   如果输入参数是实际数字，`setScore()`函数将把输入参数保存为`GameInfo.score`类，如下面的代码所示：

```js
this.setScore = function(score){
  if(typeof score == 'number')
  this.score = score;
}; 
```

+   `getScore()`方法将只返回存储在`GameInfo.score`类中的`分数值`，如下面的代码所示：

```js
this.getScore = function() {
  return this.score;
};
```

### 注意

`setScore()`和`getScore()`似乎并不太重要，但正如在查看 cookies 概念时所解释的，使用`set`和`get`语句对数据有效性进行检查是有用的。

+   `GameInfo.getSavedScore()`方法是`GameInfo.saveScore()`方法的镜像相反，如下面的代码所示：

```js
this.getSavedScore = function(){
  this.store.get('score',function(score){GameInfo.setScore(score.value) });
  return this.getScore();
};
```

1.  `getSavedScore()`方法利用`setScore()`函数将`GameInfo.score`类设置为从存储中提取的数字，然后使用`getScore()`方法返回此分数，其中可以对数据有效性进行一些额外的测试。

1.  现在，您可以随时检索最后达到的分数！

1.  我们可以调整我们的开屏，以便通过将以下代码行添加到其`draw()`函数中显示最后达到的分数。

```js
font.draw('last score: ' + GameInfo.getSavedScore(), 10,20); 
```

玩家的最后得分如下截图所示：

![使用 lawnchair 作为存储数据的多功能方式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_9.jpg)

关于数据存储的足够了，让我们快速了解一下 cookies、本地存储以及使用本地存储的更多灵活的方式：lawnchair 之间的区别。

|   | 存储大小 | 过期日期 | 信息安全 |
| --- | --- | --- | --- |
| **Cookies** | 非常有限 | 固定 | 可以在 URL 中看到，并将被发送到接收服务器和返回到本地计算机。 |
| **本地存储** | 大 | 会话或无限 | 存储在本地计算机上，没有任何东西发送到服务器和从服务器返回。 |
| **lawnchair** | 大 | 取决于所选的技术 | 存储在本地计算机上，没有任何东西发送到服务器和从服务器返回。 |

简而言之，本地存储是保存数据的新方法。你仍然可以使用 cookies，但是新的隐私规则规定你必须在使用它们之前征得许可。

总结完整的数据存储概念，我们得出结论：

+   lawnchair 应用程序是一个可自由下载的代码包，可以处理所有客户端存储需求。它可以使用多种方法保存，如永久 DOM 存储或 Webkit-SQLite。

+   推荐的可下载代码包位于[`github.com/jmo84/Lawnchair-plugin-for-ImpactJS`](https://github.com/jmo84/Lawnchair-plugin-for-ImpactJS)，因为它带有一个 ImpactJS 插件。

+   利用 lawnchair 存储系统包括包含库并将我们的`GameInfo`类的变量初始化为 lawnchair 应用程序的对象。然后我们可以通过使用`this`对象来存储和检索数据，因为它继承了所有的 lawnchair 方法。

# RPG 的额外功能

在这一部分，我们将看一些额外的功能，这些功能可能对于像我们在第三章中设计的 RPG 游戏特别有用，*让我们建立一个角色扮演游戏*。首先，我们将通过鼠标点击实现角色移动，这对于移动游戏特别有用，因为触摸屏幕相当于点击鼠标。然后我们将添加一个智能生成点。这个生成点首先检查生成实体是否会导致碰撞，并相应地调整其生成坐标。第三个元素是玩家和非玩家角色（NPC）之间的对话。最后一个附加功能是基本的头顶显示（HUD），允许玩家跟踪他们的健康状况。

## 通过鼠标点击移动玩家

直到现在，我们通过键盘箭头键移动我们的玩家。这是非常直观的，但有时是不可能的。如果你在 iPad 或其他移动设备上打开游戏，由于没有箭头键，你无法移动你的角色。在这种情况下，如果我们的角色只需朝着我们在屏幕上触摸的位置走就更有用了。在 ImpactJS 中，鼠标点击和触摸被视为相同的东西，这取决于设备。因此，通过鼠标点击实现移动自动导致了移动触摸设备。要使玩家通过点击鼠标或触摸屏幕移动，需要按照以下步骤进行：

1.  在`main.js`文件中，将鼠标点击绑定到名为`'mouseclick'`的动作。

```js
ig.input.bind(ig.KEY.MOUSE1, 'mouseclick');
```

1.  打开`player.js`文件并添加一些额外的初始变量。一旦我们开始使用即将添加的鼠标功能，我们将需要这个。

```js
name: "player",
movementspeed : 100,
mousewalking : 0,
takemouseinput : 0,
animSheet: new ig.AnimationSheet|( 'media/player.png', 32, 48 ),
```

1.  如果`movementspeed`变量还不是一个`"player"`属性，确保现在添加它。`mousewalking`命令是一个标志变量；值为`1`表示玩家必须按鼠标点击的命令行走。当鼠标被点击并且目标坐标被计算后，`takemouseinput`变量的值被设置为`1`，然后立即返回到`0`。没有这个变量，可能会通过鼠标位置来操纵你的角色，而不是单击一次。这是一个选择的问题；通过鼠标位置而不是鼠标点击来操纵可以成为有效和直观的控制方案的一部分。

1.  使用以下代码将`mousemovement()`方法添加到`"player"`实体：

```js
mousemovement: function(player){
if (player.mousewalking == 1 && player.takemouseinput == 1){
  player.destinationx = ig.input.mouse.x + ig.game.screen.x;
  player.destinationy = ig.input.mouse.y + ig.game.screen.y;
  player.takemouseinput = 0;
}
else if(player.mousewalking == 1){
  var distancetotargetx = player.destinationx - player.pos.x - (player.size.x/2) ;
  var distancetotargety = player.destinationy - player.pos.y -(player.size.y/2) ;
  if (Math.abs(distancetotargetx) > 5 ||Math.abs(distancetotargety) > 5){
    if (Math.abs(distancetotargetx) > Math.abs(distancetotargety)){
      if (distancetotargetx > 0){
        player.vel.x = player.movementspeed;
        var xydivision = distancetotargety / distancetotargetx;
        player.vel.y = xydivision * player.movementspeed;
        player.currentAnim = player.anims.right;
        player.lastpressed = 'right';
      }
      else{
        player.vel.x = -player.movementspeed;
        var xydivision = distancetotargety /Math.abs(distancetotargetx);
        player.vel.y = xydivision * player.movementspeed;
        player.currentAnim = player.anims.left;
        player.lastpressed = 'left';
      }
      }
    else{
      if (distancetotargety > 0){
        player.vel.y = player.movementspeed;
        var xydivision = distancetotargetx / distancetotargety;
        player.vel.x = xydivision * player.movementspeed;
        player.currentAnim = player.anims.down;
        player.lastpressed = 'down';
      }
      else{
        player.vel.y = -player.movementspeed;
        var xydivision = distancetotargetx /Math.abs(distancetotargety);
        player.vel.x = xydivision * player.movementspeed;
        player.currentAnim = player.anims.up;
        player.lastpressed = 'up';
      }
      }
    }
  else{
    player.vel.y = 0;
    player.vel.x = 0;
    player.mousewalking = 0;
    player.currentAnim = player.anims.idle;
  }
}
},
```

1.  这个函数的长度可能有点令人生畏，但实际上相同的逻辑被重复了几次。该函数基本上有两个功能：它可以设置目的地坐标，也可以使玩家朝着目标移动。在大多数情况下，不需要计算新的目标。因此，第一个检查是是否需要使用新的目的地。为此，`player.takemouseinput`和`player.mousewalking`变量都需要为`true`。在计算目标位置坐标时，对游戏屏幕的位置进行了修正。

1.  然后，函数继续进行实际的移动；是否进行移动由`player.mousewalking`变量的值（`True`或`False`）设置。

1.  如果玩家需要行走，实际距离将被计算到目标的 x 和 y 轴，并存储在本地变量`distancetotargetx`和`distancetotargety`中。当目标在任一轴上与玩家相距 5 像素时，玩家将不会移动。

1.  然而，如果距离大于 5 像素，玩家将以线性方式朝着目标移动。为了确保玩家以预设的移动速度移动，他将在剩余距离最大的轴上这样做。假设玩家在 x 轴上离目标很远，但在 y 轴上不那么远。在这种情况下，他将以 x 轴上的预设移动速度移动，但在 y 轴上的速度小于预设移动速度。此外，他将面向左或右，而不是上或下。

1.  两个最重要的触发变量：`player.mousewalking`和`player.takemouseinput`的初始值为`0`；当鼠标点击被注册时，它们需要被设置为`1`。我们在`update()`函数中执行此操作，如下面的代码所示：

```js
if( ig.input.pressed('mouseclick')){
this.mousewalking = 1;
this.takemouseinput = 1;
}
```

1.  我们刚刚确保游戏在每个新帧都会检查鼠标是否被点击。

1.  如果我们现在通过添加对`mousemovement()`方法的调用来调用我们的更新函数，玩家将在屏幕上注册鼠标点击的地方行走。

```js
mousemovement();
```

1.  当然，我们的键盘控件仍然存在，这将导致问题。为了使两种控制方法都能正常工作，我们只需要在按下键盘上的任意一个键时，将`player.mousewalking`变量的值设置为`0`，如下面的代码所示，用于上箭头键：

```js
if(ig.input.state('up')){
  this.mousewalking = 0;
  this.vel.y =this.movementspeed;
  this.currentAnim = this.anims.up;
  this.lastpressed = 'up';
}
```

1.  需要不断使用以下代码来检查`player.mousewalking`变量的值是否为`0`。如果不是，我们的旧控制系统将立即停止移动，因为没有注册键盘输入。

```js
Elseif(this.mousewalking == 0){
  this.vel.y = 0; 
  this.vel.x = 0;
  this.currentAnim = this.anims.idle;
}
```

1.  最后，保存您的文件并重新加载游戏。

现在，您应该能够通过在屏幕上的任何位置单击鼠标来四处走动。如果玩家遇到障碍物，您可能会注意到轻微的航向调整。但是，如果障碍物太大，玩家就不够聪明去绕过它。作为玩家，您需要自己避开障碍物。

让我们看看如何创建一个智能的生成位置。但在这样做之前，让我们回顾一下刚刚讨论的内容：

+   能够通过鼠标点击移动玩家是一个有趣的功能，尤其是在移动到移动设备时，因为在那里键盘不是一个选项。在 ImpactJS 中，鼠标的点击被视为与触摸 iPad 屏幕相同。

+   目前，我们的玩家可以使用键盘四个方向键移动，因此我们需要实现同时使用键盘方向键和鼠标的可能性。所有这些调整将在玩家实体内进行。

+   我们引入了一个名为`mousemovement()`的新方法，该方法在玩家的`update`函数中被重复调用。在任何时候，我们的方法都会检查是否给出了通过鼠标点击移动的命令，如果是，将移动玩家到所需位置。

+   除了添加这个新方法，我们还需要调整旧的移动代码，以便允许同时使用箭头键和新实现的鼠标点击移动。

## 添加智能生成位置

在 Weltmeister 中构建关卡时，可以立即将敌对实体添加到关卡本身。这很好，但有时增加一些不可预测性会增加游戏的重玩价值。这可以通过添加智能生成来实现：在随机位置生成敌人，但考虑到其他实体和碰撞层的碰撞。为了做到这一点，我们需要按照以下步骤创建一个新的插件：

1.  创建一个新文件，并将其保存为`spawnlocations.js`。

1.  将`'plugins.functions.spawnlocations'`命令添加到你的`main.js`文件中。

1.  创建一个`ig.spawnlocations`变量，作为 ImpactJS 类的扩展，如下面的代码所示：

```js
ig.module('plugins.functions.spawnlocations').defines(function(){
  ig.spawnlocations = ig.Class.extend({
  });
})
```

1.  添加`spawnIf()`方法，这是一个回调函数，如下面的代码所示。当满足某些条件时，它可以再次调用自身。

```js
spawnIf: function(x, y)
{
  if (this.CollisionAt(x,y) || this.getEntitiesAt(x,y)){
    var x1 = x + Math.round(Math.random())*10;
    var x2 = x + Math.round(Math.random())*10;
    this.spawnIf(x1,x2); //recursion
  }
  ig.game.spawnEntity('EntityEnemy', x, y);
},
```

1.  `spawnIf()`函数接受一个 x 和 y 的起始坐标，并检查是否与碰撞层或实体发生碰撞。如果是这种情况，原始坐标将在两个轴上的随机像素数上进行调整。然后，这些新坐标将被重新提交给`spawnIf()`函数，直到找到一个空闲位置。一旦不再检测到碰撞，敌人就会在那个位置生成。它需要的`CollisionAt()`和`getEntitiesAt()`函数也是`spawnlocations`类的一部分。

1.  `getEntitiesAt()`函数将检测与需要生成的敌人重叠的实体。以下代码描述了`getEntitiesAt()`函数应用的检测过程：

```js
getEntitiesAt: function(x, y)
{
  var n = ig.game.entities.length;
  var ents = [];
  for (var i=0; i<n; i++)
  {
    var ent = ig.game.entities[i],
    x0 = ent.pos.x,
    x1 = x0 + ent.size.x,
    y0 = ent.pos.y,
    y1 = y0 + ent.size.y;
    if (x0 <= x && x1 > x && y0 <= y && y1 > y)
      return true;
  }
  return false;
},
```

1.  逐个检查实体，以查看它们是否重叠，使用它们的位置、宽度和高度。如果与单个实体重叠，循环将被中止，`getEntitiesAt()`函数将返回值`true`。如果没有检测到重叠，它将返回值`false`。

1.  虽然`getEntitiesAt()`函数检查与其他实体的可能碰撞，`CollisionAt()`函数检查敌人是否会与碰撞层重叠，如下面的代码片段所示：

```js
CollisionAt: function(x,y)
{
  var Map = ig.game.collisionMap;
  var ent = new EntityEnemy();
  var res = Map.trace( x, y, x+ ent.size.x,y + ent.size.y,ent.size.x,ent.size.y ); // position, distance, size
  // true if there is a collision on either x or y axis 
  return res.collision.x || res.collision.y;
}
```

1.  最重要的功能是`collisionMap`方法的`trace()`函数。`trace()`函数将检查`x`坐标值和`x`和`ent.size.x`变量坐标值之和之间，或者`y`坐标值和`y`和`ent.size.y`变量坐标值之和之间是否有东西。最后两个参数是实体的`size`。这通常用于检查轨迹，但我们用它来检查特定位置。如果在 x 轴或 y 轴上发生碰撞，`CollisionAt()`函数将返回值`true`，`spawnIf()`函数将需要寻找新的生成位置。

1.  我们需要做的最后一件事是实际生成一个敌人。我们可以在`main.js`文件的`MyGame`中使用以下代码来实现：

```js
var spaw = new ig.spawnlocations();
spaw.spawnIf(100,200);
```

1.  如果有空闲空间，敌人现在将在这些坐标生成，否则，坐标将被调整，直到找到合适的位置。

现在我们在游戏中添加了智能生成点，是时候转向一个相对复杂的游戏元素：对话。然而，在开始对话过程之前，让我们快速回顾一下我们刚刚做的事情：

+   智能生成点的目的是找到一个敌人生成的开放空间。为此，需要检查游戏中已有的实体和关卡的碰撞层。

+   我们构建了一个包含三个部分的插件：

+   一个回调函数，将调整坐标直到找到一个合适的位置，并随后生成敌人。它利用了我们生成点类中的其他两个函数。

+   必须检查潜在与其他实体的重叠的函数。

+   检查与碰撞层的重叠的函数。

+   现在可以通过初始化一个新的生成点并使用其`spawnIf()`方法将新的敌人放入游戏世界来向游戏添加敌人。

## 介绍基本对话

许多角色扮演游戏（RPG）中有玩家和一些不可玩角色（NPC）之间的对话。在本节中，我们将介绍一种将简单对话添加到游戏中的方法。主要前提是我们在本章前面为游戏添加的对话数据。我们需要构建一个包含可以由玩家选择的对话菜单，具体步骤如下。我们可爱的 NPC Talkie 将作为我们的合作伙伴，玩家不仅在 Talkie 说话时有几个回答选项，而且 NPC 还会根据玩家想说的话做出反应，开启新的选项。这个循环应该能够一直进行，直到所有选项耗尽或对话被突然中止：

1.  打开一个新文件，并将其保存为`menu.js`，放在`plugins`文件夹的`conversation`子文件夹中。

1.  在你的`main.js`文件中添加一个`'plugins.conversation.menu'`命令。

1.  创建一个`window.Menu`类，作为 ImpactJS 类的扩展，如下面的代码所示：

```js
ig.module(
  'plugins.conversation.menu'
)
.defines(function(){
  window.Menu = ig.Class.extend({
    init: function(_font,_choice_spacing,_choices,_entity){
      this.selectedChoice = 0;
      this.cursorLeft = ">>";
      this.cursorRight = "<<";
      this.cursorLeftWidth =_font.widthForString(this.cursorLeft);
      this.cursorRightWidth =_font.widthForString(this.cursorRight);
      var i,labeled_choice;
      for(i=0;i<_choices.length;i++){
        _choices[i].labelWidth =_font.widthForString(_choices[i].label);
      } 
      this.font = _font;
      this.choices = _choices;
      this.choice_spacing = _choice_spacing;
      this.entity = _entity;
      this.MenubackgroundMenubackground = newig.Image('media/black_square.png');
      this.Menubackground.height = this.choices.length *this.choice_spacing;
    }
  }
},
```

1.  我们的菜单`init()`函数将需要四个输入变量；我们将把它们都转换为`menu`属性，以便它们在我们的`menu`方法中可用；这四个输入变量如下：

+   `_font`：这是我们将使用的字体

+   `_choice_spacing`：这是我们希望在屏幕上显示的每个选择之间的间距

+   _choices：这是玩家在对话特定部分拥有的选择数组

+   `_entity`：这是需要与玩家交谈的 NPC；在这种情况下，将是`Talkie`

1.  我们的`init()`方法包含一些其他重要的变量，如下所示：

+   `this.selectedChoice`：这是将存储当前选定选择的数组索引的变量。它被初始化为值`0`，这始终是任何数组的第一个元素，因此也是玩家的第一个选项。`this.selectedChoice`变量很重要，因为符号`<<`和`>>`将显示在当前选定选项的两侧，作为视觉辅助。

+   `this.cursorLeft`和`this.cursorRight`：它们是存储视觉辅助符号`<<`和`>>`的变量。

+   `this.cursorLeftWidth`和`this.cursorRightWidth`：它们是存储所选字体的`<<`和`>>`符号的长度的变量，以便在实际在屏幕上绘制选择时可以考虑到这一点。

+   `_choices[i].labelWidth`：这个局部变量存储了为每个选择计算出的宽度。计算出的宽度然后存储在菜单属性数组`choices[i].labelWidth`中。`cursorLeftWidth`和`cursorRightWidth`变量将用于确定在屏幕上绘制选项时的屏幕定位。

+   `this.Menubackground`：这个变量将保存一个黑色的正方形，作为背景，以便对话的白色字符始终可读，无论当前级别的外观如何。背景会根据最长选项的长度和选项的数量自适应。这样就不会占用比绝对必要更多的空间。

1.  `draw()`方法包含所有菜单逻辑，因此我们将使用以下代码分块讨论它：

```js
draw: function(_baseX, _baseY){
  var _choices = this.choices;
  var _font = this.font;
  var i,choice,x,y;
  if (this.choices.length > 0){
    var Menubackground = newig.Image('media/black_square.png');
    Menubackground.height = this.choices.length *this.choice_spacing;
    Menubackground.width = 1;
    for(var k=0;k<_choices.length;k++){
      choice = _choices[k];
      if(this.font.widthForString(choice.label)>Menubackground.width){
        Menubackground.width =this.font.widthForString(choice.label);
      }
    }
  Menubackground.width = this.Menubackground.width +this.cursorLeftWidth + this.cursorRightWidth + 16;
  Menubackground.draw(_baseX-this.Menubackground.width/2,_baseY);
  };
}
```

1.  `draw()`函数的第一个主要功能是调整菜单的背景，使其始终足够大，以适应不同的句子，给定所选择的字体。这种逻辑，以及其他逻辑，实际上可以存储在`update()`函数中，而不是`draw()`函数中。这是一个选择问题，您当然可以根据自己的意愿重写`menu`类。最重要的共同属性是`draw()`和`update()`函数都在每一帧中被调用。在下面的代码中，我们可以查看`draw()`函数的功能：

```js
for(i=0;i<_choices.length;i++){
  choice = _choices[i];
  choice.labelWidth = _font.widthForString(choice.label);
  y = _baseY + i * this.choice_spacing + 2;
  _font.draw(choice.label, _baseX, y,ig.Font.ALIGN.CENTER);
  if (this.selectedChoice === i){
    x = _baseX - (choice.labelWidth / 2) -this.cursorLeftWidth - 8;
    _font.draw(this.cursorLeft, x, y - 1);
    x = _baseX + (choice.labelWidth / 2) + 8;
    _font.draw(this.cursorRight, x, y - 1);
  }
}
```

1.  现在确定文本的位置，并将每个选项写在屏幕上。检查当前选择的选项。这个选项被**<<**和**>>**符号包围，以使玩家意识到他即将做出的选择。为了添加这些功能，我们将查看以下代码：

```js
if(ig.input.pressed('up')){
  this.selectedChoice--;
  this.selectedChoice = (this.selectedChoice < 0) ? 0 :this.selectedChoice;
}
else if(ig.input.pressed('down')){
  this.selectedChoice++;
  this.selectedChoice = (this.selectedChoice >=_choices.length) ?_choices.length-1 : this.selectedChoice;
}
else if(ig.input.pressed('interact')){var chosen_reply_key = _choices[this.selectedChoice].npcreply();ig.game.spawnEntity('EntityTextballoon',this.entity.pos.x -10,this.entity.pos.y - 70,{wrapper:npc_con.NPC_SPEECH[chosen_reply_key]});
  this.choices =_choices[this.selectedChoice].changechoices(chosen_reply_key);
}
```

1.  玩家有三个选项：他可以按上箭头、下箭头或键盘上的交互按钮；最后的动作状态对应*Enter*键。在这里，我们将解释如何在常规桌面上实现这一点。尝试为移动设备实现这一点是一个很好的练习：

+   如果激活了`'up'`输入状态，则`'up'`状态当前应该绑定到键盘的上箭头，并且所选选项向上移动一个位置。在数组中，这意味着一个具有较低索引的元素。但是，如果达到索引中的位置 0，它就不能再往下走了，因为这是第一个选项。在这种情况下，它会停留在第一个选项。

+   使用下箭头键向下移动菜单时使用相同的逻辑。

+   如果`'interact'`状态尚未绑定到*Enter*键，请通过在`main.js`文件中添加`ig.input.bind( ig.KEY.ENTER, 'interact' );`命令来绑定。玩家通过按下*Enter*键来做出选择。使用`npcreply()`函数，NPC 知道该说什么，并将生成一个包含他回复的文本气球。根据这个回复，`this.choices`函数将填充新的供玩家选择的选项。

1.  菜单由不同的项目组成；每个单独的选项对应一个单独的菜单项。使用以下代码将此菜单项类添加到`menu.js`文件中：

```js
window.MenuItem = ig.Class.extend({
  init: function(label,NPC_Response){
    this.label = label;
    this.NPC_Response = NPC_Response;
    this.entity = entity;
    },
  });
});
```

1.  菜单项使用以下两个输入参数进行初始化：

+   标签，这是一个选择或选项的实际文本。

+   `NPC_Response`，这是 NPC 回复的主键。有了这个键，就可以查找 NPC 需要回答的内容，并为玩家构建新的选项。

1.  `npcreply()`方法使用`NPC_Response`键（如下面的代码所示）查找 NPC 在我们在本章前面构建的`NPC_CON`数组中将要给出的回复的数组编号：

```js
npcreply: function(){
  for(var i= 0;i<=npc_con.NPC_CONVO_KEY.length; i++){
    if (npc_con.NPC_CONVO_KEY[i] == this.NPC_Response){
    return i;
    }
  }
},
```

1.  你可能还记得，我们的整个对话只有两个数组：

+   `NPC_CON`：这个数组包含了 NPC 要说的一切

+   `PC_CON`：这个数组包含了玩家可以说的一切

1.  在菜单代码中，该键存储在一个名为`chosen_reply_key`的局部变量中，然后以以下两种方式重新使用：

+   使 NPC 回复

+   通过将其作为参数输入到`changechoices()`方法来构建新的选项

1.  最后，`changechoices()`方法接受 NPC 所说的内容（如下面的代码所示），并通过遍历我们在本章前面构建的`PC_CON`数组来构建新的选项。

```js
changechoices: function(chosen_reply_key){
  var choices =  []
  for(var k= 0;k<=pc_con.REPLY_SET_KEY.length; k++){
    if (pc_con.REPLY_SET_KEY[k] ==npc_con.REPLY_SET_KEY[chosen_reply_key]){
      choices.push(new MenuItem(pc_con.PC_SPEECH[k],pc_con.NPC_CONVO_KEY[k]));
    }
  }
return choices;
}
```

对话是一个循环，理论上可以永远进行下去。然而，我们仍然需要一个开始。我们可以通过在`Talkie` NPC 本身中初始化我们的`Talkie` NPC 菜单的一些选项来实现这一点。这是一个非常实用的方法，但与此对话插件的整个实现一样，您可以自由地根据自己的意愿进行调整和扩展。

在我们开始与他交谈之前，我们仍然需要调整我们的`Talkie`实体：

1.  打开`talkie.js`文件，并将以下代码添加到文件中作为属性：

```js
var i;
this.choices = [
new MenuItem(pc_con.PC_SPEECH[0],pc_con.NPC_CONVO_KEY[0],this),
new MenuItem(pc_con.PC_SPEECH[1],pc_con.NPC_CONVO_KEY[1],this),
new MenuItem(pc_con.PC_SPEECH[2],pc_con.NPC_CONVO_KEY[2],this)
];
var menufont = new ig.Font('media/04b03.font.png');
this.contextMenu = new Menu(menufont,8,this.choices,this);
```

1.  我们现在为 Talkie 添加了一个对话菜单，并将其初始化为`PC_CON`数组的前三个选项。

1.  现在我们需要一个函数来检查 Talkie 是否被实际选择。否则，如果我们同时引入多个 NPC，就会出现冲突。为了检查 Talkie 是否被实际选择，我们编写以下代码：

```js
checkSelection:function(){
  this.mousecorrectedx = ig.input.mouse.x + ig.game.screen.x;
  this.mousecorrectedy = ig.input.mouse.y + ig.game.screen.y;
  return (
    (this.mousecorrectedx >= this.pos.x && this.mousecorrectedx <=this.pos.x+this.animSheet.width)&& (this.mousecorrectedy >= this.pos.y && this.mousecorrectedy <=this.pos.y+this.animSheet.height)
    );
  },
}
```

1.  该函数将检查鼠标点击的位置，并校正其在游戏屏幕上的位置。如果我们的级别完全适合视口，则不需要校正，但这几乎永远不是这种情况，因此需要进行校正。该函数返回一个`true`或`false`值。如果实体被选择，则返回值为`true`，如果没有选择，则返回`false`。

1.  在我们的`update()`方法中，我们现在可以检查鼠标点击，并使用以下代码查看 Talkie 是否被实际选择：

```js
if( ig.input.pressed('mouseclick') ) {
  this.contexted = this.checkSelection();
}
```

1.  如果是这样，我们将设置它全新的属性`contexted`为`true`。如果没有选择 Talkie，`contexted`将被设置为`false`。

1.  如果`Talkie`实体被点击并且有菜单可用，它将在`Talkie`实体下方绘制以下代码：

```js
draw: function() {
  if(this.contexted && this.contextMenu){
    this.contextMenu.draw(this.pos.x+(this.animSheet.width/2)-ig.game.screen.x,this.pos.y+(this.animSheet.height)-ig.game.screen.y);
  }
this.parent();
},
```

1.  现在 Talkie 已经准备好交谈了！一定要尝试设置自己的对话，并在游戏中看到它展开。

在我们继续讨论一些高级 AI 之前，我们将添加一个漂亮的条形图，直观地显示玩家的生命值。但在这样做之前，我们将首先回顾一下对话插件：

+   我们想要在玩家和 NPC 之间建立一段对话。为此，我们将利用本章早些时候导入的数据和一个名为`Menu`的新插件。

+   `Menu`插件由两部分组成：菜单本身和菜单中的选项。我们将两者都创建为`ImpactJS`类的扩展。

+   设置了`Menu`插件和菜单项之后，我们友好的 NPC Talkie 需要进行一些额外的调整。当玩家用鼠标点击`Talkie`实体时，应该出现一个带有几个选项的菜单。当选择其中一个选项时，Talkie 会回复。为了显示回复，我们利用了在第三章中创建的对话气泡，*让我们建立一个角色扮演游戏*。

+   整个对话是一个循环，当玩家或 NPC 用完句子，或者玩家走开时，循环结束。

## 添加基本的头顶显示

我们的玩家有生命值，但他不知道自己在任何给定时间剩下多少。因为作为玩家，了解自己剩下多少生命值是如此重要，所以我们将在屏幕上显示这一点，作为数字和生命条。为此，我们使用以下步骤构建自己的 HUD 插件：

1.  打开一个新文件，并将其保存为`hud.js`，放在`plugin`文件夹的`hud`子文件夹下。

1.  将`'plugins.hud.hud'`命令添加到`main.js`脚本中。

1.  首先在新的`plugin`文件中插入以下代码：

```js
ig.module('plugins.hud.hud').
defines(function(){
  ig.hud = ig.Class.extend({ 
    canvas  : document.getElementById('canvas'), //get the canvas
    context : canvas.getContext('2d'),
    maxHealth  : null,
    init: function(){
      ig.Game.inject({
        draw: function(){
          this.parent();
          // draw hud if there is a player
          if(ig.game.getEntitiesByType('EntityPlayer').length  !=0){
            if (this.hud){
            this.hud.number();
            this.hud.bar();
            } 
          }
        }
      })
    }, 
  }
}
```

1.  像往常一样，我们基于 ImpactJS 类定义一个新类。我们初始化两个变量：canvas 和 context，这将允许我们查看游戏是否正在被查看。此外，我们以值`null`初始化一个`maxHealth`变量。然而，与通常的条件不同，我们使用了注入技术，就像我们构建调试面板时所做的那样。在扩展代码时，您创建原始代码的新实例，并为其提供新名称。它在所有方面都是原始代码的副本，唯一的区别是您添加的额外代码。但在注入时，您修改原始代码。在这种情况下，我们覆盖了游戏的`draw()`函数。`this.parent()`函数指向我们以前的`draw()`函数，因此已经存在的所有内容都被保留。我们添加的是检查玩家实体是否存在。如果玩家在游戏中，将绘制 HUD。我们的 HUD 由两部分组成：数字和生命条。

1.  `number`函数将绘制一个黑色并略微透明的矩形，其中健康值将可见，使用以下代码：

```js
number: function(){ 
  if(!this.context) return null;
  var player =ig.game.getEntitiesByType('EntityPlayer')[0];
  // draw a transparant black rectangle 
  var context = this.canvas.getContext('2d');
  context.fillStyle = "rgb(0,0,0)";
  context.setAlpha(0.7); //set transparency 
  context.fillRect(10,10,100,30);
  //draw text on top of the rectangle 
  context.fillStyle = "rgb(255,255,255)";
  context.font = "15px Arial";
  context.fillText('health: ' + player.health,20,30);
  //font used is the default canvas font
  context.setAlpha(1);
  return null;
},
```

1.  在我们的`number()`函数的第一部分中，我们定义并绘制了矩形。由于它需要位于数字下方，所以需要先绘制它。与以前不同的是，我们直接使用 canvas 元素的属性在屏幕上绘制。例如，字体不需要使用 ImpactJS 的`ig.font`函数来设置。如下所示，您可以通过直接访问画布并设置画布的`font`属性来将字符写入屏幕。我们在这里使用的画布属性非常简单，列举如下：

+   `fillstyle`: 此属性将设置颜色

+   `font`: 此属性将设置字体

+   `setAlpha()`: 此属性将设置透明度，值为`1`表示完全不透明，值为`0`表示完全透明

+   `fillRect()`: 此属性将在给定位置以给定宽度和高度向屏幕绘制一个矩形

+   `fillText()`: 此属性将在屏幕上的特定位置绘制文本

1.  我们的生命条功能的工作方式与数字功能类似，如下面的代码所示：

```js
bar: function(){
  if(!this.context) return null;
  var player = ig.game.getEntitiesByType('EntityPlayer')[0];
  // draw a transparant black rectangle 
  var h = 100*Math.min(player.health / this.maxHealth,100);
  var context = this.canvas.getContext('2d');
  context.fillStyle = "rgb(0,0,0)";
  context.setAlpha(0.7);
  context.fillRect(10,50,100,10);
  //either draw a blue or red rectangle on top of theblack one var color = h < 30 ? "rgb(150,0,0)" :"rgb(0,0,150)";
  context.fillStyle = color;
  context.setAlpha(0.9);
  context.fillRect(10,50,h,10);
  context.setAlpha(1);
  return null;
},
```

1.  在这里，我们在彼此之上绘制了两个矩形。底部的矩形始终是黑色的，并且略微透明。顶部的矩形要么是蓝色的，要么是红色的，这取决于玩家剩余的健康程度。如果玩家的健康值为`30`或更高，条将是蓝色的，否则将是红色的，表示即将死亡。

1.  黑色透明底部条的大小始终相同，但其宽度取决于玩家开始游戏时的健康状况。我们可以使用`setMaxHealth()`方法来捕获这一点，如下面的代码所示：

```js
setMaxHealth: function(health){
  this.maxHealth = health;
}
```

1.  现在我们所需要做的就是初始化一个 HUD，并使用我们的`setMaxHealth()`方法提供玩家的健康值。将以下代码添加到`main.js`文件中：

```js
MyGame = ig.Game.extend({
  font: new ig.Font( 'media/04b03.font.png' ),ai: new ig.general_ai(),
 hud: new ig.hud(),
  init: function() {
    this.loadLevel(LevelLevel1);
 var player = ig.game.getEntitiesByType('EntityPlayer')[0];
 this.hud.setMaxHealth(player.health);
  }
}
```

1.  重新加载游戏时，我们现在应该有一个蓝色的生命条，并指示我们还剩下**100**的**生命**值，如下面的屏幕截图所示：![添加基本 HUD](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_10.jpg)

1.  然而，与敌人进行了一场小战斗后，我们可以通过我们的红色生命条看到，现在是时候去找医生了，如下面的屏幕截图所示：![添加基本 HUD](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_11.jpg)

现在我们已经看过了一些有趣的扩展内容第三章，*让我们建立一个角色扮演游戏*，让我们重新审视我们的人工智能，并引入新的复杂性。在继续之前，让我们快速回顾一下我们构建 HUD 的方式：

+   HUD 或抬头显示器提供了玩家几个关键指标的快速视图，这有助于玩家取得成功。在射击游戏中，这显示了他还剩多少弹药，总共和当前弹夹中的数量。它还可以指示其他物品或他的总得分。在这里，我们允许他使用经典的生命条来跟踪他的健康状况。

+   `hud`插件是 ImpactJS 类的扩展，有两个元素：数字和有颜色的条。它们在`hud`插件内部有各自的方法。您可以通过添加代表其他可跟踪统计数据的新方法来扩展`hud`插件。

+   在构建 HUD 时，我们使用`canvas`属性作为使用 ImpactJS 类（如`ig.font`）的替代方法。

# 人工智能：集体意识

在第三章中，*让我们建立一个角色扮演游戏*，我们已经涵盖了 AI 以及为什么行为应该与决策过程分开。我们也已经看过策略，但只应用了单一策略：攻击。在这里，我们将建立一个补充的智能层，决定哪个实体将遵循哪种策略。因为决策过程考虑了同一级别中的所有敌人，我们称之为集体意识智能。这与蜂巢的女王或战场上的将军非常相似，他们决定谁应该攻击，谁应该留在原地。我们在集体意识中决定的策略被发送到我们在第三章中放置的 AI，那里它被解释并转化为行为。行为命令又被发送到实体本身，然后实体根据它们行动。让我们使用以下步骤创建我们的`ai`插件：

1.  打开一个新文件，将其保存为`general_ai.js`。

1.  在`main.js`文件中插入`'plugins.ai.general_ai'`类。

1.  将`ig.general_ai`类创建为 ImpactJS 类扩展。通常，类`general_ai.js`已经按照以下代码创建：

```js
ig.module('plugins.ai.general_ai').
defines(function(){
  ig.general_ai = ig.Class.extend({
    init: function(){
      ig.ai.STRATEGY = { Rest:0,Approach:1};
  },
}
```

1.  我们首先要做的是定义可能的策略。在这里，我们只会发布两种策略：`Approach`或`Rest`。

1.  `getStrategy()`函数位于我们的集体意识决定保留它的地方，它是我们的 AI 将调用以接收策略的函数。这个策略又通过以下代码转化为行为：

```js
getStrategy: function(ent){
  // part 1: get player and list of enemies
  var playerList = ig.game.getEntitiesByType('EntityPlayer');
  var player = playerList[0];
  var EnemyList = ig.game.getEntitiesByType('EntityEnemy');
  // part 2: store distance to player if that enemy has enoughhealth to attack
  var distance =  [];
  for(var i = 0;i < EnemyList.length; i++){
    //for every enemy > 100 health: put in array
    EnemyList[i].health > 100 ?distance.push(EnemyList[i].distanceTo(player)) : null;
  }
  // part 3: decide on strategy: attack or stay put?var Mindist = Math.min.apply(null,distance);
  var strategy = (ent.distanceTo(player)===Mindist ||distance.length === 0) ? ig.ai.STRATEGY.Approach:ig.ai.STRATEGY.Rest;
  return strategy;
}
```

1.  `getStrategy()`方法包含我们整个集体意识逻辑，并由三个主要部分组成：

+   首先，敌人列表和玩家实体分别分配给本地变量。

+   然后，这些本地变量被用来计算每个敌人与玩家之间的距离，对于那些具有超过 100 生命值的敌人。每个生命值低于 100 的敌人都被认为是虚弱的，太害怕攻击。通过为每个敌人添加个性，可以使这段代码变得更加复杂。例如，我们可以初始化每个敌人的`courage`属性，填充一个在我们敌人的生命范围内的随机数；在我们的情况下，这是`0`到`200`。这样我们可以通过将当前生命值与勇气进行比较来决定某个敌人是否足够勇敢地攻击，而不是与固定值进行比较。当然，你可以尝试这个方法；它为游戏增加了深度和不可预测性。

+   最后，所有足够勇敢攻击的敌人都将根据它们与目标的距离进行比较，只有最接近目标的敌人才会攻击。其他人将被分配`Rest`策略，只有当它们成为周围最近的敌人时才会攻击。作为玩家，你仍然应该小心。如果他们中没有一个感到足够强大来单独攻击，他们将联合起来一起攻击。

1.  在我们之前构建的 AI 中，我们现在需要使用以下代码调用`getStrategy()`函数：

```js
getAction: function(entity){
this.entity = entity;
if(ig.game.ai.getStrategy(entity) == ig.ai.STRATEGY.Approach){

```

1.  如果策略是`Approach`，AI 将将其转化为适当的动作。

```js
return this.doAction(ig.ai.ACTION.Rest);
```

1.  如果策略是其他的，它会立即转化为`Rest`动作。因为我们只有这两种策略，所以这是有意义的。如果你有更多的策略，你将需要更多的检查。

现在我们已经扩展了我们的 AI 以包含策略，是时候来看一下本章的最后一部分了：使用 Playtomic 实现游戏分析。在继续之前，让我们快速回顾一下集体意识 AI：

+   集体意识是一个高层决策机构，将向游戏中的不同实体发布策略。这是一种使它们作为一个团体而不是一群无组织的个体行动的方式。

+   在第三章*让我们建立一个角色扮演游戏*中，我们有决策过程，这被转化为行为。现在我们有了一个策略，这转化为个体决策，然后转化为行为。

+   集体意识插件与我们在第三章*让我们建立一个角色扮演游戏*中构建的 AI 是分开的。这样我们仍然可以通过只进行少量代码更正来返回我们的个体主义 AI。

+   集体意识逻辑遵循三个主要步骤：

+   获取关卡内的所有敌人和玩家。

+   检查每个敌人的健康值，看看他是否是一个适合攻击的候选人。

+   从这些可行的敌人中选择一个离玩家最近的敌人让他攻击。敌人将如何执行这次攻击并不是由总体 AI 指定的；这是个体 AI 的决定。

# 实施 Playtomic 进行游戏分析

Playtomic 可以被视为游戏的 Google Analytics。你可以标记游戏的某些部分，并检查它们是否经常被使用。例如，如果你的游戏中有一个隐藏关卡，你可以通过标记这个隐藏关卡的`loadlevel()`函数来查看它被多少不同的玩家发现了多少次。然后你就可以确定它可能太容易或太难被发现，然后相应地调整你的游戏。但这只是你可以应用游戏统计的众多方式之一。然而，你需要意识到标记你的游戏会在一定程度上影响其性能。因此，标记代码的每一寸可能并不像预期的那样富有成效。此外，你将留下大量的数据需要分析，这可能是一项艰巨的任务。

除了为你提供游戏使用情况的见解外，Playtomic 还允许你在他们的服务器上存储一些东西，比如得分，你可以将其转化为排行榜。

如果这一切听起来对你来说都不错，那么请务必前往[`playtomic.com/`](https://playtomic.com/)创建一个免费账户。

然而，需要适当地警告一下。Playtomic 仍处于起步阶段，这意味着会有一些错误或不合逻辑的选择。例如，默认的保存得分到排行榜的做法是不覆盖第一个，即使新的得分更高。这对于排行榜来说是没有意义的，即使文档中也指出默认设置应该允许得分覆盖。与 Playtomic 服务器的连接会减慢游戏加载速度，并且经常会因为没有建立稳定连接而丢失数据。

但即使在实施、服务器速度和文档中存在缺陷，如果你想要收集有关你的游戏的见解，Playtomic 还是值得一看的。以下截图描述了 Playtomic 收集的数据及其表示：

![实施 Playtomic 进行游戏分析](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_12.jpg)

为了实施 Playtomic，你需要做一些事情：

1.  创建一个 Playtomic 账户并获取你的数据传输凭据。你需要这些来建立与他们服务器的连接。

1.  在`index.html`文件中，我们需要包含 Playtomic 源脚本，如下面的代码所示。当然，要检查最新版本是什么，在安装时。在撰写本书时，它是 2.2 版本，但这些东西发展得很快。

```js
<body>
  <canvas id="canvas"></canvas>
  <script type="text/javascript"src="img/playtomic.v2.2.min.js"></script>
</body>
```

1.  打开一个新文件，并将其保存为`PlayTomic.js`，放在`plugins`文件夹的`data`子文件夹下。在这里，我们将放置我们需要与 Playtomic 一起工作的函数。

1.  将此插件文件包含在我们的`main.js`脚本中，如下面的代码行所示：

```js
'plugins.data.PlayTomic'
```

1.  使用以下代码定义`PlayTomic`插件模块：

```js
ig.module('plugins.data.PlayTomic').
defines(function(){
// module to store and retrieve things with Playtomic
ig.PlayTomic= ig.Class.extend({
userName : null,
success: true,
scores: null,
init: function(){
  ig.log('Trying to start Playtomic...');
  try{
 Playtomic.Log.View( 951388, 'b05b606fc66742b9','f41f965c47a14bcfa7adee84eff714', document.location );
    //your login credentials
    Playtomic.Log.Play();//game start
    ig.log('loading Playtomic success ...')//could connectmessage
  }
  catch(e){
    this.success = false; //could not connect
    ig.log('Failed loading Playtomic ...')//could notconnect message
  }
},
```

1.  我们的新 Playtomic 类将负责在 Playtomic 服务器上保存玩家的分数。但是，首先需要建立与服务器的连接；这是在`init()`函数中完成的。在实现和测试 Playtomic 设置时，在关键时刻插入日志消息非常有用。您需要在上述代码的突出部分填写自己的连接凭据。

1.  一旦我们建立了连接，我们就需要发送数据。由于我们要保存分数，我们需要一个`saveScore`方法，如下面的代码所示：

```js
saveScore: function(name, score1){
  var score = {Name: name, Points: score1};
  Playtomic.Leaderboards.Save(score,'highscores',this.submitComplete,{allowduplicates:true});
},
```

1.  `Playtomic`类有一个**leaderboards**属性，您可以使用其`save()`方法保存玩家的分数。您需要指定要保存到高分榜中并添加分数的值。您可以在 Playtomic 网站的**leaderboards**设置中自己命名表格，如下截图所示：![Implementing Playtomic for game analytics](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_13.jpg)

1.  我们添加了一个可选函数，用于在提交成功时给我们反馈。在使用 Playtomic 时，强烈建议跟踪所有发送和接收的数据。作为最后一个参数，我们将允许在排行榜上重复，以便一个人可以在榜单上有多个分数。

1.  `submitComplete()`函数只是我们跟踪特定数据传输是否成功的一种方式：

```js
submitComplete: function( response ){
  if( response.Success ){
    ig.log( 'Successfully Logged!' ); //submit success
    ig.log( response );
  }
  else{
    ig.log( 'Unable to Save High Score!' ); //submit fail
  }
},
```

1.  现在，我们唯一需要做的就是集成我们的`PlayTomic`分析，如下所示的代码，使用我们为使用 lawnchair 应用程序保存分数而构建的`GameInfo.saveScore()`函数：

```js
this.PlayTom = new ig.PlayTomic();
this.saveScore = function(){
  this.store.save({score:this.score});
  if(this.PlayTom.success){
    try{
    //service sometimes failes to load
      this.PlayTom.saveScore(this.userName,this.score);}
      catch(e){
        ig.log("Could not load to Playtomic");
      }
    }
  }
}
```

1.  我们的`saveScore()`方法现在不仅通过 lawnchair 应用程序在本地保存分数，还将结果发送到 Playtomic 服务器，在那里它将被放入排行榜中，如下截图所示：![Implementing Playtomic for game analytics](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-impact/img/4568_5_14.jpg)

Playtomic 还有很多内容没有涵盖到，但这将由您自行发现。通过这个简单的介绍，您应该已经有信心开始自己的游戏分析了。不过，请注意隐私规定适用且不断变化。最好在保留游戏统计数据时征得玩家的许可，并确保在实现 Playtomic 代码时考虑到这一点。

总结介绍 Playtomic 在我们的游戏中的完整过程，我们得出结论：

+   Playtomic 是移动游戏的谷歌分析工具，免费且相对容易实现。

+   在创建 Playtomic 帐户后，您需要的第一件事是连接到他们的脚本，该脚本可以包含在您的`index.html`文件中。

+   需要建立与 Playtomic 服务器的连接。这是使用您的帐户凭据完成的，尽管您可以使用示例代码中的凭据进行测试。

+   本介绍的目标是将游戏平台上的分数发送到 Playtomic 服务器，以便在排行榜中表示。为此，我们制作了自己的 Playtomic 插件。

# 摘要

在本章中，我们看了一些您可以在游戏中做的更高级的事情，并将它们应用到我们在第三章中设计的 RPG 游戏中。

我们构建了一个介绍、胜利和游戏结束的屏幕，并让我们的游戏提示玩家的名字，以便在介绍屏幕上显示。

我们深入研究了如何通过单元测试调试代码，并制作了自己的 ImpactJS 调试面板。然后，我们看了一下处理数据的方法以及在玩家设备上存储数据的方法。RPG 增加了一些有趣的元素，比如通过鼠标点击移动玩家的方法，智能生成点，NPC 对话和生命条。

我们通过引入高层次的策略决策来增强我们的人工智能，比如集体智慧。最后，我们看了一下 Playtomic 以及如何将玩家分数发送到 Playtomic 数据库。

在下一章中，我们将看一看音乐和音效。目标是获得开始制作你的第一款游戏所需的基本声音和音乐。
