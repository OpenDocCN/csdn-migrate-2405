# HTML5 多人游戏开发（二）

> 原文：[`zh.annas-archive.org/md5/58B015FFC16EF0C30C610502BF4A7DA3`](https://zh.annas-archive.org/md5/58B015FFC16EF0C30C610502BF4A7DA3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：减少网络延迟

现在我们有一个允许多个玩家在同一个或多个游戏房间中存在的工作游戏，我们将迭代并解决在线游戏中一个非常重要的问题，即网络延迟。考虑到你将需要在未来很多年里思考这个问题，我们将非常专注于本章涵盖的主题。

在本章中，我们将讨论以下原则和概念：

+   处理多人游戏中的网络延迟

+   在客户端实现本地游戏服务器

+   客户端预测

+   插值真实位置以纠正错误的预测

# 处理网络延迟

尽管你可能是那些拥有千兆互联网连接的幸运公民之一，但你应该知道世界上大多数地方肯定不那么幸运。因此，在开发在线多人游戏时需要牢记的一些最重要的事情是，并非所有玩家都拥有相同的网络速度，也并非所有玩家都拥有高速连接。

从本节中你需要记住的主要观点是，只要玩家和游戏服务器之间存在网络（或者两个玩家直接连接在一起），就会存在延迟。

的确，并非所有游戏都需要在网络上具有几乎即时的响应时间，例如，回合制游戏，比如国际象棋，或者我们的贪吃蛇实现，因为游戏的 tick 比大多数动作游戏要慢得多。然而，对于实时、快节奏的游戏，即使是 50 毫秒的小延迟也会使游戏变得非常卡顿和令人讨厌。

想象一下这种情况。你按下键盘上的右箭头键。你的游戏客户端告诉服务器你的意图是向右移动。服务器最终在 50 毫秒后收到你的消息，运行其更新周期，并告诉你将你的角色放在位置（23，42）。最后，另外 50 毫秒后，你的客户端接收到服务器的消息，按下键盘的那一刻，你的玩家开始朝着你想要的位置移动。

![处理网络延迟](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_04_01.jpg)

正如前几章中提到的，网络延迟问题最常用的解决方案是改变客户端逻辑，使其能够立即响应用户输入，同时向服务器更新其输入。然后，权威服务器根据每个客户端的输入更新自己的游戏状态，最后向所有客户端发送游戏世界当前状态的版本。然后这些客户端可以更新自己，以便与服务器同步，整个过程继续进行。

![处理网络延迟](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_04_02.jpg)

因此，正如你可能已经意识到的那样，目标根本不是消除延迟，因为这在物理上是不可能的，而只是将其隐藏在一个不断更新的游戏后面，以便玩家产生游戏正在实时由服务器更新的错觉。

只要玩家觉得游戏反应灵敏，并且表现符合玩家的期望，从实际目的来看，你已经解决了网络延迟问题。在与服务器的每次通信（或者从服务器到客户端），问问自己延迟在哪里，以及如何通过保持游戏进行来隐藏它，而数据包在传输过程中。

## 在同步客户端中锁定步伐

到目前为止，我们已经讨论了客户端-服务器结构，其中服务器是游戏的最终权威，客户端对游戏逻辑几乎没有或根本没有权威。换句话说，客户端只是接受玩家的任何输入，并将其传递给服务器。一旦服务器向客户端发送更新的位置，客户端就会渲染游戏状态。

在线多人游戏中常用的另一种模型是锁步方法。在这种方法中，客户端尽可能频繁地告诉服务器有关玩家收到的任何输入。然后服务器将此输入广播给所有其他客户端。然后客户端依次使用每个参与者的输入状态进行下一个更新周期，并且理论上，每个人最终都会得到相同的游戏状态。每当服务器进行锁步（从每个客户端的输入数据运行物理更新）时，我们称之为一个回合。

为了使服务器保持对游戏的最终控制权，服务器的模拟也会运行更新周期，并且模拟的输出也会广播给客户端。如果客户端的更新状态与服务器发送的状态不同，客户端会认为服务器的数据是正确的，并相应地更新自己。

# 固定时间步

我们在服务器代码中将要更新的第一件事是游戏循环，它将做的第一件不同的事情是不再有增量时间的概念。此外，我们需要在更新周期之间排队每个客户端的所有输入，以便在运行物理更新时，我们有数据来更新游戏状态。

由于我们现在使用了一致的时间步长，我们不需要在服务器上跟踪增量时间。因此，服务器在客户端的角度也没有增量时间的概念。

例如，想象一个赛车游戏，玩家以每秒 300 像素的速度驾驶。假设这个特定的客户端以每秒 60 帧的频率运行游戏。假设汽车在整个秒内保持稳定的速度，那么经过 60 帧，汽车将行驶 300 像素。此外，在每帧期间，汽车将平均行驶 5 像素。

现在，假设服务器的游戏循环配置为每秒 10 帧，或者每 100 毫秒运行一次。汽车现在每帧将行驶更远（30 像素而不是 5 像素），但最终，它也将比一秒前行驶 300 像素。

![固定时间步](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_04_03.jpg)

总之，虽然客户端仍然需要跟踪处理单个帧需要多长时间，以便所有客户端以相同的速度运行，但是服务器的游戏循环不关心这一切，因为它不需要关心。

```js
// ch4/snake-ch4/share/tick.js

var tick = function (delay) {
    var _delay = delay;
    var timer;

    if (typeof requestAnimationFrame === 'undefined') {
        timer = function (cb) {
            setImmediate(function () {
                cb(_delay);
            }, _delay);
        }
    } else {
        timer = window.requestAnimationFrame;
    }

    return function (cb) {
        return timer(cb);
    }
};

module.exports = tick;
```

在这里，我们首先更新了我们为重用服务器代码以及发送到浏览器的代码而构建的 tick 模块。请注意使用`setImmediate`而不是`setTimeout`，因为回调函数在执行队列中提前调度，理论上会更快。

此外，观察我们如何导出包装器 tick 函数，而不是它返回的闭包。这样我们可以在导出函数之前配置服务器的计时器。

最后，由于增量时间现在是可预测和一致的，我们不再需要 tick 的变量来模拟时间的流逝。现在，我们可以在每次 tick 之后直接将间隔值传递给回调函数。

```js
// ch4/snake-ch4/share/game.js

var tick = require('./tick.js');
tick = tick(100);

var Game = function (fps) {
    this.fps = fps;
    this.delay = 1000 / this.fps;
    this.lastTime = 0;
    this.raf = 0;

    this.onUpdate = function (delta) {
    };

    this.onRender = function () {
    };
};

Game.prototype.update = function (delta) {
    this.onUpdate(delta);
};

Game.prototype.render = function () {
    this.onRender();
};

Game.prototype.loop = function (now) {
    this.raf = tick(this.loop.bind(this));

    var delta = now - this.lastTime;
    if (delta >= this.delay) {
        this.update(delta);
        this.render();
        this.lastTime = now;
    }
};
```

您唯一会注意到的区别是`tick`模块被调用的频率与传入的频率相同，因此我们可以配置它的运行速度。

### 注意

您可能会想知道为什么我们选择了服务器游戏循环每秒 10 次更新的可能任意的数字。请记住，我们的目标是让玩家相信他们实际上正在与其他玩家一起玩一个很棒的游戏。

我们可以通过精心调整服务器以快速更新，以便准确度不会太偏离，同时又足够慢以使客户端可以以不太明显的方式移动，从而实现这种实时游戏的错觉。

您需要在提供准确游戏状态的权威服务器和客户端提供对玩家的响应体验之间找到平衡。您更新客户端的频率越高，来自服务器更新周期的数据的模拟就越不准确；这取决于模拟需要处理多少数据，并且可能会在途中丢弃数据以保持高更新频率。同样，您更新客户端的频率越低，客户端的响应性就越低，因为它需要在服务器上等待更长时间，直到确定正确的游戏状态。

# 同步客户端

由于服务器不断推送有关游戏世界当前状态的更新，我们需要一种方式让客户端消耗和利用这些数据。实现这一点的简单方法是在游戏类之外保存最新的服务器状态，并在数据可用时更新自身，因为它不会在每次更新`tick`时都存在。

```js
// ch4/snake-ch4/share/app.client.js

// All of the requires up top
// …

var serverState = {};

// …

socket.on(gameEvents.client_playerState, function(data){
    otherPlayers = data.filter(function(_player){

        if (_player.id == player.id) {
            serverState = _player;
            return false;
        }

        _player.width = BLOCK_WIDTH;
        _player.height = BLOCK_HEIGHT;
        _player.head.x = parseInt(_player.head.x / BLOCK_WIDTH, 10);
        _player.head.y = parseInt(_player.head.y / BLOCK_HEIGHT, 10);
        _player.pieces = _player.pieces.map(function(piece){
            piece.x = parseInt(piece.x / BLOCK_WIDTH, 10);
            piece.y = parseInt(piece.y / BLOCK_HEIGHT, 10);

            return piece;
        });

        return true;
    });
});
```

在这里，我们将`serverState`变量声明为模块范围的全局变量。然后，我们修改了套接字监听器，当服务器更新其他所有玩家的状态时，我们现在寻找代表英雄的玩家的引用，并将其存储在全局`serverState`变量中。

有了这个全局状态，我们现在可以在客户端的更新方法中检查其存在并相应地采取行动。如果在给定的更新周期开始时状态不存在，我们就像以前一样更新客户端。如果来自服务器的世界状态确实在下一个客户端更新`tick`开始时对我们可用，我们就可以将客户端的位置与服务器同步。

```js
// ch4/snake-ch4/share/app.client.js

game.onUpdate = function (delta) {

    if (serverState.id) {
        player.sync(serverState);

        // On subsequent ticks, we may not in sync any more,
        // so let's get rid of the serverState after we use it
        if (player.isSyncd()) {
            serverState = {};
        }
    } else {
        player.update(delta);
        player.checkCollision();

        if (player.head.x < 0) {
            player.head.x = parseInt(renderer.canvas.width / player.width, 10);
        }

        if (player.head.x > parseInt(renderer.canvas.width / player.width, 10)) {
            player.head.x = 0;
        }

        if (player.head.y < 0) {
            player.head.y = parseInt(renderer.canvas.height / player.height, 10);
        }

        if (player.head.y > parseInt(renderer.canvas.height / player.height, 10)) {
            player.head.y = 0;
        }
    }
};
```

`Player.prototype.sync`的实际实现将取决于我们的错误校正策略，这将在接下来的几节中描述。最终，我们将希望同时整合传送和插值，但现在，我们只需检查是否需要任何错误校正。

```js
// ch4/snake-ch4/share/snake.js

var Snake = function (id, x, y, color_hex, width, height) {
    this.id = id;
    this.color = color_hex;
    this.head = {
        x: x,
        y: y
    };
    this.pieces = [this.head];
    this.width = width || 16;
    this.height = height || 16;
    this.readyToGrow = false;
    this.input = {};

    this.inSync = true;
};

Snake.prototype.isSyncd = function(){
    return this.inSync;
};

Snake.prototype.sync = function(serverState) {
    var diffX = serverState.head.x - this.head.x;
    var diffY = serverState.head.y - this.head.y;

    if (diffX === 0 && diffY === 0) {
        this.inSync = true;
        return true;
    }

    this.inSync = false;

    // TODO: Implement error correction strategies here

    return false;
};
```

对`snake`类的更改非常直接。我们添加一个标志，让我们知道在单个更新周期后是否仍需要与服务器状态同步。这是必要的，因为当我们决定在两个点之间进行插值时，我们需要多个更新周期才能到达那里。接下来，我们添加一个方法，用于验证玩家是否与服务器同步，这将决定`snake`如何更新给定的帧。最后，我们添加一个执行实际同步的方法。现在，我们只是检查是否需要更新我们的位置。随着我们讨论不同的错误校正策略，我们将更新`Snake.prototype.sync`方法以利用它们。

# 使用本地游戏服务器预测未来

我们将使用的策略是使客户端响应灵活，但受限于权威服务器，我们将根据玩家的输入来告诉服务器。换句话说，我们需要接收玩家的输入并预测由此对游戏状态的影响，同时等待服务器返回玩家行动的实际输出。

客户端预测可以总结为您对权威更新之间应该发生的事情的最佳猜测。换句话说，我们可以在客户端重用一些更新游戏世界的服务器代码，以便我们对玩家输入的输出应该是与服务器模拟的几乎相同。

## 报告用户输入

我们将改变客户端的控制机制。我们不仅会在本地跟踪我们的位置，还会通知服务器玩家按下了一个键。

```js
// ch4/snake-ch4/share/app.client.js

document.body.addEventListener('keydown', function (e) {
    var key = e.keyCode;

    switch (key) {
        case keys.ESC:
            game.stop();
            break;

        case keys.SPACEBAR:
            game.start();
            break;

        case keys.LEFT:
        case keys.RIGHT:
        case keys.UP:
        case keys.DOWN:
            player.setKey(key);
            socket.emit(gameEvents.server_setPlayerKey, {
                    roomId: roomId,
                    playerId: player.id,
                    keyCode: key
                }
            );

            break;
    }
});
```

当然，直接在事件处理程序的回调中执行这个操作可能会很快地使服务器不堪重负，所以一定要及时向上报告。一种方法是使用`tick`更新来联系服务器。

```js
// ch4/snake-ch4/share/app.client.js

game.onUpdate = function (delta) {
    player.update(delta);
    player.checkCollision();

    // …

    socket.emit(gameEvents.server_setPlayerKey, {
            roomId: roomId,
            playerId: player.id,
            keyState: player.input
        }
    );
};
```

现在，我们以与本地模拟相同的频率更新服务器，这不是一个坏主意。然而，你可能还要考虑将所有网络逻辑放在`game`类（`update`和`render`方法）之外，以便将游戏的网络方面完全抽象出来。

为此，我们可以将 socket 发射器直接放回到控制器的事件处理程序中；但是，我们不会立即调用服务器，而是使用定时器来保持更新一致。这个想法是，当按下一个键时，我们立即用更新调用服务器。如果用户在一段时间内再次按下一个键，我们会等待一段时间再次调用服务器。

```js
// ch4/snake-ch4/share/app.client.js

// All of the requires up top
// …

var inputTimer = 0;
var inputTimeoutPeriod = 100;

// …

document.body.addEventListener('keydown', function (e) {
    var key = e.keyCode;

    switch (key) {
        case keys.ESC:
            game.stop();
            break;

        case keys.SPACEBAR:
            game.start();
            break;

        case keys.LEFT:
        case keys.RIGHT:
        case keys.UP:
        case keys.DOWN:
            player.setKey(key);

            if (inputTimer === 0) {
                inputTimer = setTimeout(function(){
                    socket.emit(gameEvents.server_setPlayerKey, {
                            roomId: roomId,
                            playerId: player.id,
                            keyCode: key
                        }
                    );
                }, inputTimeoutPeriod);
            } else {
                clearTimeout(inputTimer);
                inputTimer = 0;
            }

            break;
    }
});
```

在这里，`inputTimer`变量是对我们使用`setTimeout`创建的定时器的引用，我们可以随时取消，直到定时器实际触发。这样，如果玩家非常快地按下许多键（或者长时间按住一个键），我们可以忽略额外的事件。

这种实现的一个副作用是，如果玩家长时间按住同一个键，包裹对`socket.emit`调用的定时器将继续被取消，服务器将永远不会收到后续按键的通知。虽然这乍一看可能是一个潜在的问题，但实际上这是一个非常受欢迎的特性。首先，在这个特定游戏的情况下，按两次或更多次相同的键没有效果，我们真的不需要向服务器报告额外的按键。其次（这对任何其他类型的游戏也适用），我们可以让服务器假设，在玩家按下右箭头键后，右键仍然被按下，直到我们告诉服务器停止。由于我们的`Snake`游戏没有按键释放的概念（这意味着蛇将一直朝着最后按下的方向移动，直到我们改变它的方向），服务器将继续以给定的方向移动蛇，直到我们按下不同的键并告诉服务器以新的方向移动。

# 错误校正

一旦服务器获得了每个玩家的输入状态、位置和意图，它就可以进行锁步转向并更新整个游戏世界。因为在个别玩家进行移动时，他或她只知道在特定客户端发生了什么，可能会出现的情况之一是另一个玩家可能会在他们的本地客户端以一种导致两个玩家之间发生冲突的方式进行游戏。也许，只有一个水果，两个玩家同时试图接近它，或者可能是另一个玩家撞到了你，你现在要承受一些伤害。

这就是权威服务器发挥作用的地方，让所有客户端保持一致。每个客户端在孤立状态下预测的结果现在应该与服务器确定的结果相匹配，这样每个人都可以看到游戏世界处于相同的状态。

这是一个经典的例子，说明网络延迟可能会妨碍有趣的多人游戏体验。假设两个玩家（玩家 A 和玩家 B）开始朝着同一个水果前进。根据每个玩家的模拟，他们都是从相反的方向来到水果，现在只有几帧的距离。如果没有一个玩家改变方向，他们将在完全相同的帧数到达水果。假设在玩家 A 吃掉水果之前的一帧，他因为某种原因决定改变方向。由于玩家 B 在几帧内没有从服务器获取玩家 A 的更新状态和位置，他可能会认为玩家 A 确实要吃水果，因此玩家 B 的模拟将显示玩家 A 吃水果并得分。

考虑到前面的情况，当服务器发送下一轮输出，显示玩家 A 避开了水果并没有得到任何分数时，玩家 B 的模拟应该怎么做？实际上，现在两个状态不同步（玩家 B 的模拟和服务器之间），所以玩家 B 应该与服务器更好地同步。

## 按照意图进行游戏，而不是结果

处理之前提到的情况的常见方法是包括某种动画，客户端可以根据其对玩家意图和游戏世界当前状态的了解立即开始。在我们的特定情况下，当玩家 B 认为玩家 A 即将抓住水果并获得一些分数时，他或她的模拟可以开始一个动画序列，表明玩家 A 即将通过吃水果升级。然后，当服务器回应并确认玩家 A 实际上没有吃水果时，玩家 B 的客户端可以回退到一些次要动画，表示水果未被触摸。

那些喜欢《光环》的人可能已经在与朋友进行在线游戏时注意到了这一点。当客户端尝试在游戏中扔手榴弹时，客户端会立即通知服务器。服务器然后会运行一系列测试和检查，以确保这是一个合法的举动。最后，服务器会回应客户端，告知其是否允许继续扔手榴弹。与此同时，在服务器确认客户端可以扔手榴弹时，客户端开始播放玩家扔手榴弹时的动画序列。如果这没有得到检查（也就是说，服务器没有及时回应），玩家会完成向前挥动手臂的动作，但什么也没有扔出去，在这种情况下，看起来就像是一个正常的动作。[*Aldridge*，*David* *(2011)*，*我先开枪：网络化《光环：Reach》的游戏玩法。GDC 2011*]

## 多接近才算足够接近？

另一个用例是，客户端具有游戏的当前状态以及玩家的输入信息。玩家运行下一轮的模拟并在某个位置渲染蛇。几帧后，服务器告诉客户端蛇实际上在不同的位置。我们该如何解决这个问题？

在需要改变玩家位置的情况下，如果玩家将蓝色机器人投入空中并越过底部有尖刺的坑，然后几帧后（在服务器同步所有客户端之后），我们突然看到机器人离玩家预期的位置几个像素远，可能会看起来很奇怪。然而，另一方面，有些情况下，从服务器的更新所需的调整很小，以至于简单地将玩家从 A 点传送到 B 点是不可察觉的。这将严重依赖于游戏的类型和个体情况。

![多接近才算足够接近？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_04_04.jpg)

为了我们的贪吃蛇游戏，如果我们确定我们的预测与服务器告诉我们蛇应该在的位置之间的差异只有一个单位（不是两个轴都有偏差），除非头部在两个轴上都有一个单位的偏差，但调整其中一个轴会使我们处于蛇的脖子上，那么我们可以选择传送。这样，玩家只会看到蛇的头部位置变化了一个位置。

例如，如果我们的预测将玩家的头放在点（8,15），而蛇是从右向左移动，但服务器的更新显示它应该在点（7,16），我们不会传送到新的点，因为那需要调整两个轴。

然而，如果蛇仍然向左移动，其头部现在位于点（8,15），而服务器更新将其放在点（7,15），（8,14），（8,16），（9,15），（9,14）或（9,16），我们可以简单地将头部瞬间移动到新点，然后在下一次更新时，蛇的其余部分将被重新定位。

![多接近算够接近？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_04_05.jpg)

```js
// ch4/snake-ch4/share/snake.js

Snake.prototype.sync = function(serverState) {
    var diffX = serverState.head.x - this.head.x;
    var diffY = serverState.head.y - this.head.y;

    if (diffX === 0 && diffY === 0) {
        this.inSync = true;
        return true;
    }

    this.inSync = false;

    // Teleport to new position if:
    //   - Off by one in one of the axis
    //   - Off by one in both axes, but only one unit from the neck
    if ((diffX === 0 && diffY === 1)
           || (diffX === 1 && diffY === 0)
           || (this.pieces[0].x === serverState.head.x && diffY === 1)
           || (this.pieces[0].y === serverState.head.y && diffX === 1)
    ){

        this.head.x = serverState.head.x;
        this.head.y = serverState.head.y;

        this.inSync = false;
        return true;
    }

    // TODO: Implement interpolation error correction strategy here

    return false;
};
```

您会注意到瞬间移动可能会使蛇的头部重叠，这在正常情况下会导致玩家输掉游戏。然而，当这种情况发生时，游戏不会再次检查碰撞，直到下一帧更新。此时，头部将首先向前移动，这将重新调整蛇的其余部分，从而消除任何可能的碰撞。

## 流畅的用户体验

调整玩家当前位置和服务器设置的位置之间的另一种方法是通过多帧逐渐平滑地移动到该点。换句话说，我们在当前位置和想要到达的位置之间进行插值。

插值的工作原理很简单，如下所述：

1.  首先确定您希望插值需要多少帧。

1.  然后确定每个方向上每帧需要移动多少单位。

1.  最后，在每帧中移动一点，直到在所需的帧数内到达目标点。

基本上，我们只是按照所需时间的相同百分比向目标点移动相应的百分比。换句话说，如果我们希望在 10 帧内到达目标位置，那么在每一帧我们就移动总距离的 10％。因此，我们可以将以下公式抽象出来：

*a = (1 – t) * b + t * c*

在这里，`t`是一个介于零和一之间的数字，表示 0％到 100％之间的百分比值（这是起点和目标点之间的当前距离）。

![流畅的用户体验](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_04_06.jpg)

我们可以直接在`snake`类中实现线性插值方法；然而，您内心中那个执着的面向对象的设计师可能会认为，这种数学过程更适合放在一个完全独立的实用程序类中，该类被`snake`类导入并使用。

```js
// ch4/snake-ch4/share/snake.js

Snake.prototype.interpolate = function(currFrame, src, dest, totalFrames) {
    var t = currFrame / totalFrames;

    return (1 - t) * src + dest * totalFrames ;
};
```

这种插值方法将使用（除了源点和目标点）动画中的当前帧以及动画将持续的总帧数。因此，我们需要一种方法来跟踪当前帧，并在希望重新开始动画时将其重置为零。

重置插值序列的好地方是在`socket`回调中，这是我们首次得知可能需要向不同位置插值的地方。

```js
// ch4/snake-ch4/share/app.client.js

socket.on(gameEvents.client_playerState, function(data){
    otherPlayers = data.filter(function(_player){

        if (_player.id == player.id) {
            serverState = _player;
            serverState.currFrame = 0;

            return false;
        }

        return true;
    });
});
```

然后，我们还需要更新`snake`类，以便我们可以配置每个插值周期可以处理的最大帧数。

```js
// ch4/snake-ch4/share/snake.js

var Snake = function (id, x, y, color_hex, width, height, interpMaxFrames) {
    this.id = id;
    this.color = color_hex;
    this.head = {x: x, y: y};
    this.pieces = [this.head];
    this.width = width || 16;
    this.height = height || 16;
    this.interpMaxFrames = interpMaxFrames || 3;
    this.readyToGrow = false;
    this.input = {};
    this.inSync = true;
};
```

有了这个方法，我们现在可以在我们的`sync`方法中实现线性插值，这样蛇就可以在几帧的时间内平滑地插值到其实际位置。您可以根据需要选择到达目标位置所需的帧数，也可以根据游戏的个别情况将其保持不变。

```js
// ch4/snake-ch4/share/snake.js

Snake.prototype.sync = function(serverState) {
    var diffX = serverState.head.x - this.head.x;
    var diffY = serverState.head.y - this.head.y;

    if (diffX === 0 && diffY === 0) {
        this.inSync = true;

        return true;
    }

    this.inSync = false;

    // Teleport to new position if:
    //   - Off by one in one of the axis
    //   - Off by one in both axes, but only one unit from the neck
    if ((diffX === 0 && diffY === 1) ||
        (diffX === 1 && diffY === 0) ||
        (this.pieces[0].x === serverState.head.x && diffY === 1) ||
        (this.pieces[0].y === serverState.head.y && diffX === 1)) {

        this.head.x = serverState.head.x;
        this.head.y = serverState.head.y;

        this.inSync = true;

        return true;
    }

    // Interpolate towards correct point until close enough to teleport
    if (serverState.currFrame < this.interpMaxFrames) {
        this.head.x = this.interpolate(
            serverState.currFrame,
            this.head.x,
            serverState.head.x,
            this.interpMaxFrames
        );
        this.head.y = this.interpolate(
            serverState.currFrame,
            this.head.y,
            serverState.head.y,
            this.interpMaxFrames
        );
    }

    return false;
};
```

最后，您会注意到，在我们当前的客户端-服务器设置中，客户端接收其他玩家的确切位置，因此不会对它们进行预测。因此，它们的位置始终与服务器同步，不需要错误校正或插值。

# 总结

本章的重点是减少权威服务器和运行它的客户端之间的感知延迟。我们看到了客户端预测如何可以在服务器确定玩家请求的移动和意图的有效性之前，为玩家提供即时反馈。然后，我们看了如何在服务器上使用锁步方法，以便所有客户端一起更新，并且每个客户端还可以确定性地重现游戏服务器计算出的相同世界状态。

最后，我们看了两种纠正错误客户端预测的方法。我们实现的方法是传送和线性插值。使用这两种错误校正方法可以让我们向玩家展示他们的输入应该产生的结果的一个近似，但也确保他们的多人游戏体验准确且与其他玩家的体验相同。

在下一章中，我们将迈向未来，并尝试一些较新的 HTML5 API，包括 Gamepad API，它将允许我们放弃键盘，使用更传统的游戏手柄来控制我们的游戏，全屏模式 API 和 WebRTC，它将允许我们进行真正的点对点游戏，并暂时跳过客户端-服务器模型，以及更多。


# 第五章：利用前沿技术

到目前为止，在本书中，我们已经集中讨论了与多人游戏开发相关的主题。这一次，除了**WebRTC**之外，我们将讨论一些 HTML5 中最新的 API，它们本身与多人游戏几乎没有关系，但在游戏开发的背景下提供了很多机会。

在本章中，我们将讨论以下原则和概念：

+   使用 WebRTC 直接连接对等方

+   为基于浏览器的游戏添加游戏手柄

+   在**全屏**模式下最大化您的游戏

+   访问用户的媒体设备

# HTML5-最终前沿

尽管我们在本章中将要尝试的技术令人兴奋并且非常有前途，但我们还不能过于依赖它们。至少，我们必须谨慎地使用这些 API，因为它们仍然处于实验阶段，或者规范仍处于工作草案或候选推荐阶段。换句话说，截至目前为止，在本书出版后的可预见的未来，每个功能的浏览器支持可能会有所不同，支持每个功能的 API 在不同浏览器上可能会略有不同，而 API 的未来可能是不确定的。

**万维网联盟**（**W3C**）定义了每个规范在成为最终、稳定并被视为 W3C 标准之前经历的四个开发阶段（也称为成熟级别）。这四个阶段是**工作草案**、**候选推荐**、**提议推荐**和**W3C 推荐**。

初始级别是工作草案，社区在这一级别讨论了提议的规范并定义了他们试图实现的精确细节。在这个级别上，推荐是非常不稳定的，它的最终发布几乎是不确定的。

接下来是候选推荐级别，在这个级别上从实施推荐中获取反馈。在这里，标准仍然不稳定并且可能会发生变化（或者像有时候一样被废弃），但它的变化频率比在工作草案阶段要低。

一旦规范文档作为候选推荐发布，W3C 的咨询委员会将审查提案。如果自审查期开始以来已经过去至少四周，并且文档已经得到了社区和实施者的足够认可，那么文档将被转发为推荐发布。

最后，当一个规范成为 W3C 推荐时，它将携带 W3C 的认可标志作为认可标准。遗憾的是，即使在这一点上，也不能保证浏览器会支持标准或根据规范实施它。然而，在我们这个时代，所有主要的浏览器都非常好地遵循规范，并实施所有有用的标准。

# 使用全屏模式最大化您的游戏

在本章中我们将讨论的所有 API 中，全屏是最容易理解和使用的。正如你可能已经猜到的那样，这个 API 允许你设置一个可以在全屏模式下呈现的 HTML 元素节点。

请注意，尽管全屏模式的第一个编辑草案（推荐标准成为工作草案之前的成熟级别）于 2011 年 10 月发布，但规范仍处于早期起草阶段。（有关更多信息，请参阅以下文章：*使用全屏模式*，*(2014 年 7 月)*。[`developer.mozilla.org/en-US/docs/Web/Guide/API/DOM/Using_full_screen_mode`](https://developer.mozilla.org/en-US/docs/Web/Guide/API/DOM/Using_full_screen_mode)）。

至于当前浏览器支持情况，您会发现在所有现代浏览器中使用 API 是相当安全的，尽管今天在实现上有细微差异以及如何启用全屏模式也有所不同。

在使用全屏模式时要牢记的主要事项是，您必须将单个元素设置为全屏模式。这个元素确实可以有一组元素节点的子树，但您仍然需要在特定元素上启用全屏模式。在游戏开发的背景下，您很可能会将主画布元素设置为全屏，但这不是一个硬性要求。您也可以要求浏览器通过在 body 元素上调用`requetFullscreen()`方法使整个文档进入全屏模式。

设置元素进入全屏模式和将元素退出全屏模式涉及两种方法，分别是`requestFullscreen`和`exitFullscreen`方法。请注意，截至目前，所有主要浏览器都在其各自的供应商前缀下实现了这些方法。

此外，请记住，除非用户发起的事件向浏览器发出请求，否则无法启用全屏模式。换句话说，你不能在 DOM 加载后立即尝试将 body 元素更改为全屏。同样，你也不能以编程方式触发 DOM 事件（例如在页面上触发虚假点击或使用 JavaScript 滚动页面，从而触发`onScroll`事件），并使用事件处理程序回调来欺骗浏览器，让它认为是用户发起了该操作。

```js
<!doctype html>
<html>
<head>
    <title> Fullscreen</title>
    <!-- [some custom CSS here, left out for brevity] -->
</head>
<body>
<ul>
    <li>
        <span>1</span>
    </li>
    <li>
        <span>O</span>
    </li>
    <li>
        <span>O</span>
    </li>
    <li>
        <span>1</span>
    </li>
</ul>
<script>
    var list = document.querySelector('ul');

    list.addEventListener('click', function (event) {
        var block = event.target;
        block.requestFullscreen();
    });
</script>
</body>
</html>
```

上面的代码演示了如何在元素接收到点击后将其设置为全屏模式。在这种情况下，您可能已经注意到，我们假设无论哪个浏览器执行该代码都已经放弃了他们的供应商支持，因此我们可以简单地调用`requestFullscreen()`，就像它原本的意图一样。

今天处理这个问题的更好方法是，由于浏览器尚未实现不带供应商前缀的 API 规范，因此使用 polyfill 或辅助函数来检测是否需要供应商前缀，并执行必要的操作使其正常工作。

```js
var reqFullscreen = (function () {
    var method = (function () {
        var el = document.createElement('div');
        var supported = '';
        var variations = [
            'requestFullscreen',
            'msRequestFullscreen',
            'mozRequestFullScreen',
            'webkitRequestFullscreen'
        ];

        variations.some(function (method) {
            supported = method;
            return el[method] instanceof Function;
        });

        return supported;
    }());

    return function (element) {
        element[method]();
    };
}());

var list = document.querySelector('ul');

list.addEventListener('click', function (event) {
    var block = event.target;
    reqFullscreen(block);
});
```

上面的示例代码创建了一个名为 reqFullscreen 的函数，它通过确定是否需要供应商前缀来为我们做繁重的工作；然后它记住了需要进行全屏请求的版本。然后，当我们希望元素进入全屏模式时，我们通过将其传递给该函数来调用该函数。

### 注意

似乎浏览器制造商的目标是尽可能让实验性 API 对最终用户造成困惑。在全屏模式的情况下，请注意规范将接口函数命名为`requestFullscreen`和`exitFullscreen`（其中`Fullscreen`一词仅大写第一个字母）。

除了 Mozilla Firefox 之外，每个供应商前缀都遵循规范，关于函数名称——即`webkitRequestFullscreen`和`msRequestFullscreen`。Mozilla Firefox 不同，因为它实现了`mozRequestFullScreen`，这与其他供应商不同，因为它在驼峰命名法中将`FullScreen`拼写为两个单词。最后一个细节是，Webkit 的开发人员决定同时实现两个版本：`webkitRequestFullscreen`和`webkitRequestFullScreen`，以取悦所有人。

![使用全屏模式最大化您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_01.jpg)

在上面的图像中，我们的页面不处于全屏模式。但是，当您单击其中一个元素时，该元素将以全屏模式呈现：

![使用全屏模式最大化您的游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_02.jpg)

您可能会注意到，浏览器强加的唯一要求是必须由用户操作发起请求以启用全屏模式。这并不意味着操作必须在设置为全屏的相同元素上，就像下面的例子所示：

```js
var list = document.querySelector('ul');
var btn = document.querySelector('button');

btn.addEventListener('click', function (event) {
    // Somehow determine what element to use
    var firstBlock = list.children[0].children[0];

    reqFullscreen(firstBlock);
});
```

前面的示例绑定到一个按钮元素，然后添加一个点击处理程序，将一些其他元素设置为全屏模式。

我们可以通过查找文档对象的一个自动更新的属性来检查特定元素是否处于全屏模式。

```js
var element = document.webkitFullscreenElement;
```

当您运行上述语句时，它将返回对当前处于全屏模式的任何元素的引用；否则，它将返回一个空值。

我们还可以查询文档，测试文档是否可以启用全屏。

```js
var canFullscreen = document.webkitFullscreenEnabled; // => bool
```

最后，有一个特殊的 CSS 伪选择器，允许我们定位全屏中的元素。同样，这个选择器目前也是供应商前缀的。

```js
full-screen,
:-moz-full-screen,
:-moz-full-screen-ancestor,
:-webkit-full-screen {
    font-size: 50vw;
    line-height: 1.25;
    /* … */
}
```

请注意，选择器会定位调用`requestFullscreen`的元素。在前面的示例中，指定的样式适用于**ul li span**。

# 更好地使用游戏手柄进行控制

在过去的几年里，我们已经看到 HTML5 中添加了一系列非常受欢迎和强大的新 API。这些包括 WebSockets、canvas、本地存储、WebGL 等等。在游戏开发的背景下，下一个自然的步骤是为游戏手柄添加标准支持。

与全屏模式类似，游戏手柄 API 仍处于非常早期的起草阶段。实际上，游戏手柄支持甚至比全屏模式更“原始”。尽管您会发现浏览器支持是足够的，但使用 API 可能会出现错误和有些不可预测。然而，游戏手柄 API 确实提供了一个足够好的接口，以提供出色的最终用户体验。随着规范的成熟，将游戏手柄添加到浏览器中的前景是非常令人兴奋和有前途的。

关于游戏手柄 API 的第一件事是，它与 DOM 中所有其他输入 API 的不同之处在于它不是由鼠标或键盘等事件驱动的。例如，尽管每个键盘输入都会触发一个事件（换句话说，会调用一个注册的回调），但来自连接的游戏手柄的输入只能通过手动轮询硬件来检测。换句话说，浏览器会触发与游戏手柄相关的事件，以让您知道游戏手柄已连接和断开连接。然而，除了这些类型的事件之外，浏览器不会在连接的游戏手柄上每次按键时触发事件。

要在游戏中使用游戏手柄，您首先需要等待游戏手柄连接到游戏中。这是通过注册一个回调来监听全局的`gamepadconnected`事件来实现的：

```js
/**
 * @type {GamepadEvent} event
 */
function onGamepadConnected(event) {
    var gamepad = event.gamepad;
}

window.addEventListener('gamepadconnected', onGamepadConnected);
```

`gamepadconnected`事件将在游戏运行期间任何时候在您的计算机上连接游戏手柄时触发。如果在脚本加载之前已经连接了游戏手柄，那么`gamepadconnected`事件将不会触发，直到玩家按下游戏手柄上的按钮。虽然这一开始可能看起来有点奇怪，但这一限制是有很好的原因的，即为了保护玩家不受恶意脚本的指纹识别。然而，要求用户在激活控制器之前按下按钮并不是什么大问题，因为玩家如果想玩游戏，总是需要在某个时候按下按钮。唯一的缺点是，我们一开始不知道用户是否已经连接了游戏手柄。不过，想出创造性的解决方案来解决这个限制并不是太困难的任务。

`GamepadEvent`对象公开了一个 gamepad 属性，它是对实际的 Gamepad 对象的引用，这正是我们想要的。这个对象的有趣之处在于它不像 JavaScript 中的其他对象那样自动更新。换句话说，每当浏览器接收到来自连接的游戏手柄的输入时，它会在内部跟踪其状态。然后，一旦您轮询`gamepad`状态，浏览器就会创建一个新的`Gamepad`对象，其中包含所有更新的属性，以反映控制器的当前状态。

```js
function update(){
    var gamepads = navigator.getGamepads();
    var gp_1 = gamepads[0];

    if (gp_1.buttons[1].pressed) {
        // Button 1 pressed on first connected gamepad
    }

    if (gp_1.axes[1] < 0) {
        // Left stick held to the left on first connected gamepad
    }

    requestAnimationFrame(update);
}
```

在每个`update`周期中，您需要获取游戏手柄对象的最新快照并查找其状态。

`Gamepad`对象接口定义了没有方法，但有几个属性：

```js
interface Gamepad {
    readonly attribute DOMString id;
    readonly attribute long index;
    readonly attribute boolean connected;
    readonly attribute DOMHighResTimeStamp timestamp;
    readonly attribute GamepadMappingType mapping;
    readonly attribute double[] axes;
    readonly attribute GamepadButton[] buttons;
};
```

`id`属性描述了连接到应用程序的实际硬件。如果通过某个 USB 适配器连接游戏手柄，则`id`可能会引用适配器设备，而不是实际使用的控制器。

`index`将引用`GamepadList`对象中的`Gamepad`对象，这是浏览器响应`navigator.getGamepads()`提供的。使用此索引值，我们可以获取对我们希望查询的特定游戏手柄的引用。

如预期的那样，`boolean connected`属性指示特定游戏手柄是否仍连接到应用程序。如果在调用`navigator.getGamepads()`之前游戏手柄断开连接，则基于`Gamepad.index`偏移的相应元素将在`GamepadList`中为 null。但是，如果获取了对`Gamepad`对象的引用，但硬件断开连接，那么对象的 connected 属性仍将设置为 true，因为这些属性不是动态更新的。总之，这个属性是多余的，可能会在将来的更新中从规范中删除。

我们可以通过查看`Gamepad`对象上的`timestamp`属性来检查浏览器上次更新`gamepad`状态的时间。

一个特别有趣的属性是`mapping`。其背后的想法是可以有几种标准映射，以便更容易地连接到硬件的方式对应应用程序。

![使用游戏手柄更好地控制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_04.jpg)

目前只有一个标准映射，可以通过名称`standard`来识别，如先前演示的（有关更多信息，请参阅*Gamepad W3C Working Draft 29 April 2015*。[`www.w3.org/TR/gamepad`](http://www.w3.org/TR/gamepad)）。如果浏览器不知道如何布局控制器，它将用空字符串响应`mapping`属性，并以最佳方式映射按钮和轴。在这种情况下，应用程序可能应该要求用户手动映射应用程序使用的按钮。请记住，有些情况下，方向键按钮映射到其中一个轴，因此要小心处理每种情况：

```js
var btns = {
        arrow_up: document.querySelector('.btn .arrow-up'),
        arrow_down: document.querySelector('.btn .arrow-down'),
        arrow_left: document.querySelector('.btn .arrow-left'),
        arrow_right: document.querySelector('.btn .arrow-right'),

        button_a: document.querySelector('.buttons .btn-y'),
        button_b: document.querySelector('.buttons .btn-x'),
        button_x: document.querySelector('.buttons .btn-b'),
        button_y: document.querySelector('.buttons .btn-a'),

        button_select: document.querySelector('.controls .btn- select'),
        button_start: document.querySelector('.controls .btn- start'),

        keyCodes: {
            37: 'arrow_left',
            38: 'arrow_up',
            39: 'arrow_right',
            40: 'arrow_down',

            32: 'button_a',
            65: 'button_b',
            68: 'button_x',
            83: 'button_y',

            27: 'button_select',
            16: 'button_start'
        },

        keyNames: {
            axe_left: 0,
            axe_left_val: -1,

            axe_right: 0,
            axe_right_val: 1,

            axe_up: 1,
            axe_up_val: -1,

            axe_down: 1,
            axe_down_val: 1
        }
    };

    Object.keys(btns.keyCodes).map(function(index){
        btns.keyNames[btns.keyCodes[index]] = index;
    });

function displayKey(keyCode, pressed) {
    var classAction = pressed ? 'add' : 'remove';

    if (btns.keyCodes[keyCode]) {
        btns[btns.keyCodes[keyCode]].classListclassAction;
    }
}

function update(now) {
        requestAnimationFrame(update);

        // GamepadList[0] references the first gamepad that connected to the app
        gamepad = navigator.getGamepads().item(0);

        if (gamepad.buttons[0].pressed) {
            displayKey(btns.keyNames.button_x, true);
        } else {
            displayKey(btns.keyNames.button_x, false);
        }

        if (gamepad.buttons[1].pressed) {
            displayKey(btns.keyNames.button_a, true);
        } else {
            displayKey(btns.keyNames.button_a, false);
        }

        if (gamepad.buttons[2].pressed) {
            displayKey(btns.keyNames.button_b, true);
        } else {
            displayKey(btns.keyNames.button_b, false);
        }

        if (gamepad.buttons[3].pressed) {
            displayKey(btns.keyNames.button_y, true);
        } else {
            displayKey(btns.keyNames.button_y, false);
        }

        if (gamepad.buttons[8].pressed) {
            displayKey(btns.keyNames.button_select, true);
        } else {
            displayKey(btns.keyNames.button_select, false);
        }

        if (gamepad.buttons[9].pressed) {
            displayKey(btns.keyNames.button_start, true);
        } else {
            displayKey(btns.keyNames.button_start, false);
        }

        if (gamepad.axes[btns.keyNames.axe_left] === btns.keyNames.axe_left_val){
            displayKey(btns.keyNames.arrow_left, true);
        } else {
            displayKey(btns.keyNames.arrow_left, false);
        }

        if (gamepad.axes[btns.keyNames.axe_down] === btns.keyNames.axe_down_val) {
            displayKey(btns.keyNames.arrow_down, true);
        } else {
            displayKey(btns.keyNames.arrow_down, false);
        }

        if (gamepad.axes[btns.keyNames.axe_up] === btns.keyNames.axe_up_val) {
            displayKey(btns.keyNames.arrow_up, true);
        } else {
            displayKey(btns.keyNames.arrow_up, false);
        }

        if (gamepad.axes[btns.keyNames.axe_right] === btns.keyNames.axe_right_val) {
            displayKey(btns.keyNames.arrow_right, true);
        } else {
            displayKey(btns.keyNames.arrow_right, false);
        }
    }

    window.addEventListener('gamepadconnected', function (e) {
        update(0);
    });
```

前面的示例连接了一个没有可识别映射的游戏手柄；因此，它将每个按钮分配给特定的布局。由于在这种特殊情况下，方向键按钮映射到左轴，因此当我们想要确定是否正在使用方向键时，我们会检查该状态。此演示的输出如下：

![使用游戏手柄更好地控制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_03.jpg)

通常，您可能希望为用户提供选择他们希望与您的游戏交互的方式的能力 - 使用键盘和鼠标，游戏手柄或两者兼而有之。在上一个示例中，这正是为什么`btns`对象引用看似随机和任意的`keyCode`值的原因。这些值被映射到特定的键盘键，以便玩家可以在标准键盘或游戏手柄上使用箭头键。

# 使用 WebRTC 进行点对点通信

近年来最令人兴奋的 API 之一是 WebRTC（代表 Web 实时通信）。该 API 的目的是允许用户在支持该技术的平台上进行实时流式音频和视频通信。

WebRTC 由几个单独的 API 组成，并可以分解为三个单独的组件，即`getUserMedia`（我们将在下一节中更深入地讨论）、`RTCPeerConnection`和`RTCDataChannel`。

由于我们将在下一节中讨论`getUserMedia`，所以我们将在那里时留下更详细的定义（尽管名称可能会透露 API 的预期用途）。

`RTCPeerConnection`是我们用来连接两个对等方的。一旦建立了连接，我们可以使用`RTCDataChannel`在对等方之间传输任何数据（包括二进制数据）。在游戏开发的背景下，我们可以使用`RTCDataChannel`将玩家的状态发送给每个对等方，而无需一个服务器来连接每个玩家。

要开始使用`RTCPeerConnection`，我们需要一种方法来告诉每个对等方有关另一个对等方。请注意，WebRTC 规范故意省略了应该进行数据传输的具体方式。换句话说，我们可以自由选择任何方法手动连接两个对等方。

获取`RTCPeerConnection`的第一步是实例化`RTCPeerConnection`对象，并配置它所需使用的**STUN**服务器以及与您期望的连接类型相关的其他选项：

```js
var pcConfig = {
    iceServers: [{
        url: 'stun:stun.l.google.com:19302'
    }]
};

var pcOptions = {
    optional: [{
        RtpDataChannels: true
    }]
};

var pc = new webkitRTCPeerConnection(pcConfig, pcOptions);
```

在这里，我们使用 Google 免费提供的公共`STUN`服务器。我们还使用供应商前缀以保持与本章中其他示例的一致性。截至目前，每个以某种方式实现 WebRTC 的供应商都使用供应商前缀。

### 注意

如果您对 STUN、**交互式连接建立**（**ICE**）、**NAT**、**TURN**和**SDP**不太熟悉，不用太担心。虽然本书不会深入解释这些网络概念，但您在本章中跟随示例并在自己的游戏中实现数据通道时，不需要对它们了解太多。

简而言之，STUN 服务器用于告知客户端其公共 IP 地址以及客户端是否在路由器的 NAT 后面，以便另一个对等方可以连接到它。因此，我们在创建`RTCPeerConnection`时使用一个 STUN 服务器。

再次强调简单和简洁，ICE 候选允许浏览器直接连接到另一个浏览器。

一旦我们准备好了`RTCPeerConnection`，我们通过提议与对等方连接。第一步是创建一个提议，描述了另一个客户端如何连接回我们。在这里，我们使用我们选择的协议通知其他对等方我们的提议。通常，这将使用 WebSocket 完成，但为了更明确地演示每个步骤，我们将使用人类已知的最古老的通信协议：**口头交流**：

```js
/**
 *
 */
function makeMessage(msg, user, color) {
    var container = document.createElement('p');
    var tag = document.createElement('span');
    var text = document.createElement('span');

    if (color) {
        tag.classList.add(color);
    } else if (nickColor) {
        tag.classList.add(nickColor);
    }

    tag.textContent = '[' + (user || nick) + '] ';
    text.textContent = msg;

    container.appendChild(tag);
    container.appendChild(text);

    var out = document.getElementById('out');
    var footer = document.getElementById('outFooter');
    out.appendChild(container);
    footer.scrollIntoView();
}

/**
 *
 */
function createOffer() {
    pc.createOffer(function (offer) {
        // Note #1
        makeMessage('offer: ' + encodeURIComponent(offer.sdp));

        // Note #2
        pc.setLocalDescription(new RTCSessionDescription(offer),
            // Note #3
            function () {},

            // Note #4
            function (e) {
                console.error(e);
                makeMessage('error creating offer');
            }
        );
    });
}
```

在这个 WebRTC 点对点连接的*hello world*演示中，我们将构建一个简单的聊天室，中间没有服务器（除了我们需要启动点对点连接的 STUN 服务器）。

根据前面的示例代码，我们可以假设有一些 HTML 结构，其中包含一个输入元素，我们可以在其中输入文本和命令，并使用它们来驱动 WebRTC 组件。

![使用 WebRTC 进行点对点连接](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_08.jpg)

前面的屏幕截图显示了我们调用先前显示的`createOffer`函数后的输出。我们将广泛使用`makeMessage`函数来帮助我们查看系统（即 WebRTC API）发起的消息，以及来自我们试图连接和聊天的其他对等方的消息。

前面代码示例中的`Note #1`旨在引起您对我们如何显示提议的**会话描述协议**（**SDP**）的注意，这是一种*在对等方之间协商会话能力的协议*（摘自 Suhas Nandakumar 的文章，*SDP for the WebRTC*，[`tools.ietf.org/id/draft-nandakumar-rtcweb-sdp-01.html`](http://tools.ietf.org/id/draft-nandakumar-rtcweb-sdp-01.html)）。由于协议中的换行符是有意义的，我们需要保留该字符串中的每个字符。通过对字符串进行编码，我们保证了框架提供给我们的字符串不会以任何方式被更改（尽管这使得对我们人类来说稍微不太可读）。

`注 2`显示了这种信息交换过程的第二步，这将把我们连接到另一个对等方。在这里，我们需要设置自己客户端的会话描述。你可以把这看作是你记住自己家庭地址（或邮箱，如果你喜欢与笔友进行一系列信件交流）。

`注 3`和`注 4`是我们发送给`RTCSessionDescription`构造函数的第二个和第三个参数。它们分别是成功和错误回调函数，目前我们并不太关心。实际上，我们确实关心“错误”回调函数，因为我们希望在尝试到达 STUN 服务器时等可能出现的错误时得到通知等。

现在我们有了一个`offer`对象，我们只需要让另一个对等方知道这个提议是什么样子的。构成提议的两个要素是 SDP 块和会话描述类型。

一旦我们的对等方知道 SDP 块的样子，他或她就可以实例化一个`RTCSessionDescription`对象，并设置 SDP 和类型属性。接下来，第二个对等方将该会话描述设置为自己的远程会话描述。在这种情况下，我们只需打开一个新窗口来代表第二个对等方，并通过*复制+粘贴*方法传输 SDP 字符串。

```js
function setRemoteDesc(sdp, type) {
    var offer = new RTCSessionDescription();
    offer.sdp = decodeURIComponent(sdp);
    offer.type = type;

    makeMessage('remote desc: ' + offer.sdp);

    pc.setRemoteDescription(new RTCSessionDescription(offer),
        function () {
        },
        function (e) {
            console.log(e);
            makeMessage('error setting remote desc');
        }
    );
}
```

在这里，我们为另一个客户端手动创建一个`offer`对象。我们使用从第一个客户端获得的 SDP 数据，并将第二个客户端的会话描述类型设置为`offer`。这个提议被设置为第二个客户端的远程描述。你可以把这看作是，在你写信给笔友的例子中，笔友写下你的家庭地址，这样他或她就知道该把信件寄到哪里了。

第二个对等方记下你的会话描述后，下一步就是接受该提议。在 RTC 术语中，第二个对等方需要回应这个提议。类似于我们调用`createOffer()`来创建初始提议一样，我们在`webkitRTCPeerConnection`对象上调用`createAnswer()`。这个调用的输出也是一个会话描述对象，只是它包含了第二个用户的 SDP，会话描述类型是`answer`而不是`offer`。

```js
function answerOffer() {
    pc.createAnswer(function (answer) {
        makeMessage('answer: ' + encodeURIComponent(answer.sdp));
        pc.setLocalDescription(new RTCSessionDescription(answer));
    }, function (e) {
        console.log(e);
        makeMessage('error creating answer');
    });
}
```

在这里，远程对等方首先从来自`answer`对象的 SDP 中设置自己的本地描述。然后，我们将其显示到屏幕上，这样我们就可以使用与第一个对等方（“本地对等方”）相同的信息作为远程描述。这代表了你的笔友首先记住自己的家庭地址，然后让你拥有一份副本，这样你就知道该把你的信件寄到哪里了。

现在两个对等方都知道对方可以被联系到，所需要的只是一种联系对方的方式。这种细节层次被抽象出来，不涉及数据通道。因此，在我们可以使用数据通道之前，我们需要向对等连接对象添加至少一个 ICE 候选。

当每个对等方创建他们的`offer`和`answer`对象时，对等连接对象会接收一个或多个 ICE 候选引用。在这个演示中，当我们接收到 ICE 候选时，我们将其打印到屏幕上，这样在这一点上我们可以复制和粘贴组成每个 ICE 候选的数据，因此我们可以在对方的机器上重新创建它们，并将 ICE 候选添加到对等连接对象中。

```js
pc.onicecandidate = function (event) {
    if (event.candidate) {
        makeMessage('ice candidate: ' + JSON.stringify(event.candidate), 'sys', 'sys');
    }
};

function addIceCandidate(candidate) {
    pc.addIceCandidate(candidate);
}

addIceCandidate(JSON.parse({
   /* encoded candidate object from onIceCandidate callback */
});
```

一旦每个对等方都有了另一个对等方的会话描述，并且有一个 ICE 候选来引导浏览器到另一个对等方，我们就可以开始直接从一个对等方发送消息到另一个对等方。

下一步就是简单地使用`DataChannel`对象发送和接收消息。在这里，API 与 WebSocket 的 API 非常相似，我们在通道对象上调用`send()`方法向对等方发送数据，并注册一个`onmessage`事件处理程序，从中接收对等方连接的另一侧的数据。这里的主要区别是，与 WebSocket 场景不同，我们现在直接连接到另一个对等方，因此发送消息非常快：

```js
// When creating the RTCPeerConnection object, we also create the DataChannel
var pc = new webkitRTCPeerConnection(pcConfig, pcOptions);
var channelName = 'packtRtc';
var dc = dc = pc.createDataChannel(channelName);

function sendMessage(msg) {
    if (dc.readyState === 'open') {
        var data = {
            msg: msg,
            user: nick,
            color: nickColor
        };

        // Since this is a chat app, we want to see our own message
        makeMessage(msg);

        // The actual send command
        dc.send(JSON.stringify(data));
    } else {
        makeMessage('Could not send message: DataChannel not yet open.');
    }
}

dc.onmessage = function (event) {
    var data = JSON.parse(event.data);
    makeMessage(data.msg, data.user, data.color);
};

dc.onopen = function () {
    makeMessage('dataChannel open', 'sys', 'sys');
};

dc.onerror = function (e) {
    makeMessage('dataChannel error: ' + e, 'sys', 'sys');
};

dc.onclose = function () {
    makeMessage('dataChannel close', 'sys', 'sys');
};
```

![使用 WebRTC 进行点对点通信](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_07.jpg)

总之，在我们可以开始使用`DataChannel`与其他对等方通信之前，我们需要手动（意味着在 WebRTC API 的真实领域之外）相对于彼此配置每个对等方。通常，您将首先通过 WebSocket 连接对等方，并使用该连接创建并回答发起对等方的提议。此外，通过`DataChannel`发送的数据不仅限于文本。我们可以使用另一个 WebRTC API 发送二进制数据，例如视频和音频，我们将在下一节中讨论。

# 使用媒体捕获捕获时刻

在线多人游戏的较新组件之一是涉及实时语音和视频通信的社交方面。这最后一个组件可以通过使用 HTML **媒体捕获** API 完美满足，它允许您访问玩家的摄像头和麦克风。一旦您获得了对摄像头和麦克风的访问权限，您可以将这些数据广播给其他玩家，将它们保存为音频和视频文件，甚至创建一个仅基于这些数据的独立体验。

媒体捕获的*hello world*示例可能是音频可视化演示的吸引人之处。我们可以通过媒体捕获和**Web Audio** API 的混合来实现这一点。通过媒体捕获，我们实际上可以从用户的麦克风接收原始音频数据；然后，我们可以使用 Web Audio 连接数据并对其进行分析。有了这些数据，我们可以依靠 canvas API 来呈现由麦克风接收的代表声波的数据。

首先，让我们更深入地了解媒体捕获。然后，我们将看一下 Web Audio 的重要部分，并留给您找到更好、更完整和专门的来源来加深您对 Web Audio API 的理解。

目前，媒体捕获处于候选推荐阶段，因此我们仍然需要寻找并包含供应商前缀。为简洁起见，我们将假定**Webkit 目标**（*HTML 媒体捕获 W3C 候选推荐*，（2014 年 9 月）。[`www.w3.org/TR/html-media-capture/`](http://www.w3.org/TR/html-media-capture/)）。）

我们首先在 navigator 对象上调用`getUserMedia`函数。（有关`window.navigator`属性的更多信息，请转到[`developer.mozilla.org/en-US/docs/Web/API/Window/navigator`](https://developer.mozilla.org/en-US/docs/Web/API/Window/navigator)。）在此，我们指定有关我们希望捕获的媒体的任何约束，例如音频、我们想要的视频帧速率等等：

```js
var constraints = {
    audio: false,
    video: {
        mandatory: {
            minAspectRatio: 1.333,
            maxAspectRatio: 1.334
        },
        optional: {
            width: {
                min: 640,
                max: 1920,
                ideal: 1280
            },
            height: {
                min: 480,
                max: 1080,
                ideal: 720
            },
            framerate: 30
        }
    }
};

var allowCallback = function(stream){
    // use captured local media stream
    // ...
};

var denyCallback = function(e){
    // user denied permission to let your app access media devices
    console.error('Could not access media devices', e);
};

navigator.webkitGetUserMedia(constraints, allowCallback, denyCallback);
```

在其最简单的形式中，约束字典只包括一个指示我们希望捕获的媒体类型的键，后面跟着一个代表我们意图的`Boolean`值。可选地，任何 false 值都可以通过完全省略属性来简写。

```js
var  constraints = {
    audio: true,
    video: false
};

// the above is equivalent to simply {audio: true}

navigator.webkitGetUserMedia(constraints, allowCallback, denyCallback);
```

一旦执行了对`getUserMedia`的调用，浏览器将向用户显示警告消息，提醒用户页面正在尝试访问媒体设备；这将给用户一个机会允许或拒绝这样的请求：

![使用媒体捕获捕获时刻](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_05.jpg)

尽管它与旧的`window.alert`、`window.confirm`和`window.prompt` API 不同，但浏览器生成的提示始终是异步的和非阻塞的。这就是为什么在用户允许或拒绝请求的情况下提供回调函数的原因。

一旦我们获得了对用户音频设备的访问权限，就像前面的例子一样，我们可以利用 Web Audio API 并创建一个`AudioContext`对象；从这里，我们可以创建一个媒体流源：

```js
var allowCallback = function(stream){
    var audioContext = new AudioContext();
    var mic = audioContext.createMediaStreamSource(stream);

    // ...
};
```

正如您可能已经猜到的那样，`MediaStream`对象表示麦克风作为数据源。有了这个参考，我们现在可以将麦克风连接到`AnalyserNode`，以帮助我们将音频输入分解为我们可以以可视方式表示的内容：

```js
var allowCallback = function(stream){
    var audioContext = new AudioContext();
    var mic = audioContext.createMediaStreamSource(stream);

    var analyser = audioContext.createAnalyser();
    analyser.smoothingTimeConstant = 0.3;
    analyser.fftSize = 128;

    mic.connect(analyser);

    // ...
};
```

下一步是使用`analyser`对象并从音频源获取频率数据。有了这个，我们可以根据需要将其渲染到现有画布上：

```js
var allowCallback = function(stream){
    var audioContext = new AudioContext();
    var mic = audioContext.createMediaStreamSource(stream);

    var analyser = audioContext.createAnalyser();
    analyser.smoothingTimeConstant = 0.3;
    analyser.fftSize = 128;

    mic.connect(analyser);

    var bufferLength = analyser.frequencyBinCount;
    var frequencyData = new Uint8Array(bufferLength);

    // assume some canvas and ctx objects already loaded and bound to the DOM
    var WIDTH = canvas.width;
    var HEIGHT = canvas.height;
    var lastTime = 0;

    visualize(e);

    function visualize(now) {
        // we'll slow down the render speed so it looks smoother
        requestAnimationFrame(draw);
        if (now - lastTime >= 200) {
            ctx.clearRect(0, 0, WIDTH, HEIGHT);
            analyser.getByteFrequencyData(frequencyData);

            var barWidth = (WIDTH / bufferLength) * 2.5;
            var x = 0;

            [].forEach.call(frequencyData, function (barHeight) {
                ctx.fillStyle = 'rgb(50, ' + (barHeight + 100) + ', 50)';
                ctx.fillRect(x, HEIGHT - barHeight / 1, barWidth, barHeight / 1);
                x += barWidth + 1;
            });

            lastTime = now;
        }
    }
};
```

![使用媒体捕获捕捉时刻](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_05_06.jpg)

处理视频同样简单，但是需要连接摄像头到您的计算机，这是您所期望的。如果您使用设置视频约束的`getUserMedia`请求，但没有摄像头，则将执行错误回调，并将`NavigatorUserMediaError`对象作为参数发送：

```js
navigator.webkitGetUserMedia({video: true}, function(stream){
    // ...
}, function(e){
    // e => NavigatorUserMediaError {
    //              constraintName: '',
    //              message: '',
    //              name: 'DevicesNotFoundError'
    //          }
});
```

另一方面，当视频设备可访问时，我们可以通过将其`src`属性设置为`objectUrl`的方式将其流式传输到视频元素中，该`objectUrl`指向我们从用户媒体获取的流源：

```js
var video = document.createElement('video');
video.setAttribute('controls', true);
video.setAttribute('autoplay', true);

document.body.appendChild(video);

var constraints = {
    video: true
};

function allowCallback(stream){
    video.src = window.URL.createObjectURL(stream);
}

function denyCallback(e){
    console.error('Could not access media devices', e);
}

navigator.webkitGetUserMedia(constraints, allowCallback, denyCallback);
```

# 摘要

本章使我们向前迈进了一步，让我们一窥我们可以将其纳入我们的多人游戏中的最新 HTML5 API。这些 API 包括全屏模式、游戏手柄、媒体捕获和 WebRTC。有了这些强大的附加功能，您的游戏将更具吸引力和乐趣。

然而，整个讨论中的一个要点是，本章中描述的所有 API 仍处于早期草拟阶段；因此，它们可能会受到严重的界面更改，或者也可能被弃用。与此同时，请确保为每个 API 添加适当的供应商前缀，并注意任何一次性浏览器怪癖或实现差异。

在下一章中，我们将通过讨论与网络游戏相关的安全漏洞来结束我们在 JavaScript 中进行多人游戏开发的精彩旅程。我们将描述最常见的技术，以最小化作弊的机会，从而提供公平和充分的游戏体验。


# 第六章：增加安全性和公平竞争

尽管我们现在才谈论安全性，但本章的主要要点是安全性应该内置到您的游戏中。就像其他类型的软件一样，您不能事后再加入一些安全功能，然后期望产品是无懈可击的。然而，由于本书的主要重点不是安全性，我认为我们可以理直气壮地直到最后一章才提出这个问题。

在本章中，我们将讨论以下原则和概念：

+   基于网络的应用程序中的常见安全漏洞

+   使用 Npm 和 Bower 为您的游戏增加额外的安全性

+   使游戏更安全，更不容易作弊

# 常见的安全漏洞

如果您是从软件开发的许多其他领域转向游戏开发，您会高兴地知道，保护游戏与保护任何其他类型的软件并没有太大的不同。将游戏视为需要安全性的任何其他类型的软件，尤其是分布式和网络化的软件，将帮助您制定适当的措施，以帮助您保护您的软件。

在本节中，我们将介绍一些基于网络的应用程序（包括游戏）中最基本和基本的安全漏洞，以及保护措施。然而，我们不会深入探讨更复杂的网络安全主题和情景，比如社会工程学、拒绝服务攻击、保护用户帐户、正确存储敏感数据、保护虚拟资产等等。

## 通过加密传输数据

您应该知道的第一个漏洞是，从服务器向客户端发送数据会使数据暴露给其他人。监视网络流量几乎和边走路、嚼口香糖一样容易，尽管并非每个人都有足够的技能来做这些事情。

以下是您可能要求玩家在玩游戏（或准备玩游戏）时经历的常见情景：

+   玩家输入用户名和密码以获得授权进入您的游戏

+   您的服务器验证登录信息

+   然后允许玩家继续玩游戏

如果玩家发送到服务器的初始 HTTP 请求未加密，则查看网络数据包的任何人都将知道用户凭据，您的玩家帐户将受到威胁。

最简单的解决方案是通过 HTTPS 传输任何此类数据。虽然使用 HTTPS 不能解决所有安全问题，但它确实为我们提供了相当确定的保证，其中包括以下几点：

+   服务器响应客户端请求的人应该是它所说的那样

+   服务器和客户端接收的数据不会被篡改

+   任何查看数据的人都无法以纯文本形式阅读它

由于 HTTPS 数据包是加密的，任何监视网络的人都需要解密每个数据包才能知道其中包含的数据，因此这是向服务器发送密码的安全方式。

就像没有免费的午餐一样，也没有免费的加密和解密。这意味着使用 HTTPS 会产生一些可衡量的性能损失。这种惩罚实际上是什么，以及它将是多么微不足道，这在很大程度上取决于一系列因素。关键是评估您的具体情况，并确定在性能方面使用 HTTPS 将会太昂贵的地方。

然而，请记住，至少在数据的价值大于额外性能时，以安全性为代价换取性能是值得的。由于相关的延迟，您可能无法通过 HTTPS 传输数千个玩家的位置和速度，但每个单独的用户在初始认证后不会经常登录，因此至少强制进行安全认证是任何人都无法承受的。

## 脚本注入

这个漏洞背后的基本原则是，你的脚本将用户输入作为文本（数据）并在执行上下文中将其评估为代码。这种情况的典型用例如下：

+   游戏要求用户输入他/她的名字

+   恶意用户输入代码

+   游戏可选择保存该文本以备将来使用

+   游戏最终在执行上下文中使用该代码

在基于 Web 的应用程序中，或者更具体地说，在浏览器中执行 JavaScript 时，恶意输入可能是一串 HTML，执行上下文是 DOM。DOM API 的一个特点是它能够将一个字符串设置为元素的 HTML 内容。浏览器会将该字符串转换为活动的 HTML，就像渲染在某个服务器上的任何其他 HTML 文档一样。

以下代码片段是一个应用程序的示例，该应用程序要求用户输入昵称，然后在屏幕右上角显示它。这个游戏也可能会将玩家的名字保存在数据库中，并尝试在游戏的其他部分中使用玩家的名字来渲染该字符串：

```js
/**
 * @param {Object} player
 */
function setPlayerName(player){
    var nameIn = document.getElementById('nameIn');
    var nameOut = document.getElementById('nameOut');

    player.name = nameIn.value;

    // Warning: here be danger!
    nameOut.innerHTML = player.name;
}
```

![脚本注入](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_06_01.jpg)

对于普通开发者来说，这似乎是对一个准备享受你的平台游戏的玩家的一个相当可爱的问候。只要用户输入一个没有 HTML 字符的实际名称，一切都会很好。

然而，如果用户决定称自己为`<script src="img/my-script.js"></script>`之类的东西，而我们不对该字符串进行消毒以删除使字符串成为有效 HTML 的字符，应用程序可能会受到损害。

用户利用这个漏洞的两种可能方式是改变客户端的体验（例如，输入一个使名称闪烁或下载并播放任意 MP3 文件的 HTML 字符串），或者输入一个下载并执行 JavaScript 文件的 HTML 字符串，这些文件会以恶意方式改变主游戏脚本并与游戏服务器交互。

更糟糕的是，如果我们在保护其他漏洞方面不小心，这个安全漏洞可以与其他漏洞一起被利用，进一步加剧邪恶玩家可能造成的损害：

![脚本注入](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_06_02.jpg)

## 服务器验证

根据我们如何处理和使用来自用户的输入，我们可能会通过信任未经消毒的输入来危害服务器和其他资产。然而，仅仅确保输入通常有效是不够的。

例如，某个时刻你会告诉服务器玩家在哪里，以多快的速度朝着哪个方向移动，可能还有哪些按钮被按下。如果我们需要告知服务器玩家的位置，我们首先会验证客户端游戏是否提交了一个有效的数字：

```js
// src/server/input-handler.js

socket.on(gameEvents.server_userPos, function(data){
    var position = {
        x: parseFloat(data.x),
        y: parseFloat(data.y)
    };

    if (isNaN(position.x) || isNan(position.y) {
        // Discard input
    }

    // ...
});
```

现在我们知道用户没有黑客攻击游戏，而是发送了实际位置向量，我们可以对其进行计算并更新游戏状态的其余部分。或者，我们可以吗？

例如，如果用户发送了无效的浮点数作为他们的位置（假设在这种情况下我们正在使用浮点数），我们可以简单地丢弃输入或对其尝试输入无效值做出特定的响应。但是，如果用户发送了一个不正确的位置向量，我们该怎么办？

可能是玩家从屏幕左侧移动到右侧。首先，服务器接收到玩家的坐标，显示玩家真正的位置，然后玩家报告说自己稍微靠右一点，离一个火坑更近了。假设玩家可能每帧最快移动 5 像素。那么，如果我们只知道玩家发送了一个有效的向量{`x`: `2484`, `y`: `4536`}，我们如何知道玩家是否真的在一个帧内跳过火坑（这是不可能的移动），还是玩家作弊了呢？

![服务器验证](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_06_03.jpg)

这里的关键原则是验证输入是否有效。请注意，我们谈论的是验证而不是清理用户输入，尽管后者也是必不可少的，并且与前者相辅相成。

对于玩家报告虚假位置的先前问题的一个解决方案是，我们可以简单地跟踪上次报告的位置，并将其与下一个接收到的位置进行比较。对于更复杂的解决方案，我们可以跟踪几个先前的位置，并查看玩家的移动方式。

```js
var PlayerPositionValidator = function(maxDx, maxDy) {
    this.maxDx = maxDx;
    this.maxDy = maxDy;
    this.positions = [];
};

PlayerPositionValidator.prototype.addPosition = function(x, y){
    var pos = {
        x: x,
        y: y
    };

    this.positions.push(pos);
};

PlayerPositionValidator.prototype.checkLast = function(x, y){
    var pos = this.positions[this.positions.length - 1];

    return Math.abs(pos.x - x) <= this.maxDx
         && Math.abs(pos.y - y) <= this.maxDy;
};
```

上述类跟踪了玩家在一个帧（或者服务器验证新用户位置的频率）中可能具有的最大垂直和水平位移。通过将其与特定玩家的实例相关联，我们可以添加新的传入位置，并检查它是否大于最大可能的位移。

更复杂的情况是检查和验证的一个案例是确保玩家不会报告可能已过期的事件或属性（例如临时增益等），或者无效的输入状态（例如，玩家已经在空中，但突然报告发起了一次跳跃）。

更复杂的是，还有另一种情况需要我们注意，这是非常难以检查的。到目前为止，正如我们所讨论的，对抗试图操纵游戏状态的玩家的解决方案是利用权威服务器的力量来否决客户端的操作。然而，正如我们将在下一节讨论的那样，甚至权威服务器也无法真正防止或恢复一类问题。

## 人工智能

检测玩家试图作弊的一种情况是因为报告的移动是不可能的（例如，移动得太快或者在游戏中某个级别中没有可用的武器）。然而，完全不同的是，试图检测一个作弊者因为他或她玩得太好。如果邪恶的玩家是一个机器人，完美地对抗诚实的人类玩家，这是我们可能面临的一个漏洞。

这个问题的解决方案和问题一样复杂。假设您想要防止机器人与人类竞争，您如何可能确定一系列输入是否来自另一个软件而不是人类玩家？可以假设，尽管每一步都是合法的，但准确度可能会比其他人高出几个数量级。

不幸的是，本书范围之外的代码实现展示了对抗这类问题的方法，这是本书无法涵盖的。一般来说，您将希望使用各种启发式方法来确定一系列动作是否过于完美。

# 构建安全的游戏和应用程序

既然我们已经讨论了一些需要注意的基本事项，以及在游戏中不应该执行的事项；我们现在将看一些简单的概念，这些概念是我们不能忽略的。

再次强调，大多数概念都适用于网页开发，所以来自那个领域的人会感到如鱼得水。

## 权威服务器

希望现在清楚了，拥有可信赖的信息的关键是确保信息的来源是可信赖的。在我们的情况下，我们依赖游戏服务器来监听所有客户端，然后确定当前游戏状态的真相。

如果你发现自己在考虑不使用服务器-客户端模型来进行多人游戏，而是倾向于某种替代格式，你应该牢记的一件事是，通过在两个玩家之间放置一个权威机构，可以获得这样的安全性。即使单个玩家决定操纵和作弊他或她自己的游戏客户端，权威游戏服务器也可以确保其他玩家仍然拥有公平的游戏体验。

虽然并非每种游戏格式都需要权威游戏服务器，但当你的特定游戏可以使用权威游戏服务器时，如果你不使用权威游戏服务器，你应该有一个非常好的理由。

## 基于会话的游戏玩法

现代浏览器的一个好处是它们具有非常强大的 JavaScript 引擎，使我们能够在客户端使用纯 JavaScript 做很多事情。因此，我们可以将很多繁重的工作从服务器转移到客户端。

例如，假设我们想保存当前玩家的游戏状态。这将包括玩家当前的位置、健康状况、生命、得分等，以及虚拟货币、成就等。

一种方法是对所有这些信息进行编码，并将其存储在用户的设备上。这样做的问题是用户可能会更改保存的文件，而我们却不知情。因此，这个过程中的一个常见步骤是创建最终保存文件的哈希值，然后稍后使用相同的哈希值来确保游戏的保存文件没有被更改。

### 注意

“哈希”和“加密”之间有什么区别？

也许你已经听说过这两个术语可以互换使用，但它们实际上是非常不同的概念。虽然两者都经常与安全性相关联，但这是它们唯一共享的相似之处。

哈希函数将任意长度的字符串映射到某个固定长度的字符串。给定相同的输入字符串，始终返回相同的输出哈希。哈希函数的主要特点是映射是单向的，这意味着无法通过输出来恢复原始输入。

例如，`Rodrigo Silveira`输入字符串将映射到类似`73cade4e8326`的内容。对这个输出字符串进行哈希处理将返回与其自身或原始输入完全不同的内容。

另一方面，加密是一种将某个输入字符串转换为该字符串的不同表示的方法，但具有可逆（或撤消）函数的能力，并获得原始输入字符串。

例如，如果使用凯撒密码（以强大的罗马将军命名，而不是巴西足球运动员）对 Rodrigo Silveira 字符串进行加密，使用偏移值 3（这意味着输入文本中的每个字符都向后移动 3 个字母），则输出为`Urguljr Vloyhlud`——即`R`之后的第三个字符是`U`，依此类推。如果我们对输出字符串应用偏移值`-3`，将得到原始字符串。

简而言之，就实际目的而言，哈希无法被逆转，而加密可以。

然而，如果我们还将哈希值与客户端一起存储，那么在修改游戏保存文件后，他们只需要重新计算哈希值，我们就会回到原点。

更好的方法是在服务器上计算哈希值，将哈希值存储在服务器上，并通过某种用户账户系统与玩家关联起来。这样，如果对本地存储的文件进行任何篡改，服务器可以使用只有它自己访问的哈希来验证它。

还有一些情况，您可能希望将 API 密钥或其他此类唯一对象存储在客户端。同样，这里的关键原则是，任何接触客户端的东西现在都在您的敌人控制之下，不能信任。

因此，这一部分的主要要点是始终将密钥和其他敏感数据存储在服务器内，并通过会话令牌将其与玩家关联和代理。

## 通过混淆来增加安全性

虽然混淆不是一种安全形式，但它确实增加了一层复杂性，使真正决心的（和有技能的）恶意用户减慢速度，并过滤掉大多数其他邪恶的人，否则他们会尝试利用你的游戏。

在网页开发中，混淆游戏的最常见方法是通过将最终源代码通过一些 JavaScript 编译器运行，安全地重命名变量和函数名称，并以等效于原始输入代码但执行相同任务的方式重写代码。

例如，您可能有以下代码，玩家可以通过更改一些变量的值来轻松利用他们浏览器的 JavaScript 控制台：

```js
Gameloop.prototype.update = function(){
    Players.forEach(function(player){
        hero.bullets.filter(function(bullet){
            if (player.intersects(bullet)) {
                player.takeDamage(bullet.power);
                hero.score += bullet.hp;

                return false
            }

            return true;
        });
    });

    // ...
};
```

我们不必仔细研究以前的函数，就可以意识到在这个虚构的游戏中，只有击中其他玩家的子弹才会对每个玩家造成伤害并增加我们自己的得分。因此，编写一个函数来替换它是微不足道的，或者至少修改其重要部分以达到相同的目的同样容易。

现在，通过诸如 Google 的闭包编译器之类的工具运行该函数（要了解有关闭包编译器的更多信息，请参阅[`developers.google.com/closure/compiler/`](https://developers.google.com/closure/compiler/)）将输出类似于以下内容，这显然不可能操纵，但肯定不会那么微不足道：

```js
_l.prototype.U=function(){c.forEach(function(e){i.a.filter(
function(o){return e.R(o)?(e.a4(o.d),i.$+=o.F,!1):!0})})};
```

大多数 JavaScript 混淆器程序将重命名函数名称，变量和属性，并删除不必要的空格，括号和分号，使输出程序非常紧凑且难以阅读。在部署代码之前使用这些程序的一些额外好处包括拥有较小的文件，这样您将最终发送给客户的文件（从而节省带宽），并且在闭包编译器的情况下，它会重写代码的部分，以便输出是最佳的。

这一部分的主要要点是，向您的代码添加复杂性层使其更加安全，并且至少有助于摆脱某些攻击者。就像在前门上方安装摄像头并不一定能消除潜在的闯入者一样，但它确实在吓唬不受欢迎的访客方面走了很长的路。

“然而，请记住，混淆根本不是安全。对混淆的 JavaScript 程序进行反混淆是微不足道的（即使编译的程序也可以轻松地反编译为部分源代码）。您永远不应该仅依赖混淆和模糊作为一种可靠的安全形式。混淆您的部署应用程序应该是已经安全系统的最后一步，特别是考虑到混淆的主要好处，如前面所述。

# 重复造轮子

像计算机科学中的大多数问题一样，有人已经找到了解决方案并将其转换为代码。在这方面，我们特别受益于许多慷慨（而非常聪明）的程序员，他们通过开源项目分发他们的解决方案。

在这一部分，我邀请您寻找现有的解决方案，而不是花时间编写自己的解决方案。尽管编写有趣问题的复杂解决方案总是很有趣（除非，也许，你的老板正在催促你赶上即将到来的截止日期），但您可能会发现，您的努力更好地投资于制作您的实际游戏。

正如我们在第二章中讨论的*设置环境*，拥有 Node.js 生态系统的访问权限可以让您在开发游戏时遇到的许多问题找到、使用并最终分享很多有用的工具。

遵循安全和公平竞争的主题，接下来是一个常见工具列表，我们可以通过**Npm**和**Bower**（以及**Grunt**和**Gulp**）来帮助我们处理游戏中的安全性。

## Npm 安装验证器

这个模块可以让您非常轻松地验证和消毒数据。您可以在服务器上以及在浏览器中使用验证器。只需将模块引入并在输入上调用其各种方法：

```js
var validator = require('validator');

validator.isEmail('foo@bar.com'); //=> true
validator.isBase64(inStr);
validator.isHexColor(inStr);
validator.isJSON(inStr);
```

有各种方法可以检查几乎任何类型的数据或格式，以及对数据进行消毒，这样您就不必为此编写自己的函数。

## Npm 安装 js-sha512

这个简单的模块用于使用各种算法对字符串进行哈希处理。要在浏览器中将库作为独立库使用，您还可以使用 Bower 导入它：

```js
bower install js-sha512

```

要使用`js-sha512`，只需将其`require`到所需的哈希函数，并将字符串发送给它进行哈希处理：

```js
sha512 = require('js-sha512').sha512;
sha384 = require('js-sha512').sha384;

var s512 = sha512('Rodrigo Silveira');
var s384 = sha384('Rodrigo Silveira');
```

## Npm 安装闭包编译器

正如之前提到的，谷歌的闭包编译器是一个非常强大的软件，几年前就已经开源。使用编译器可以获得的好处远远超出了简单地想要混淆代码。例如，编译器允许您使用数据类型注释您的 JavaScript 代码，然后编译器可以查看并告诉您变量是否违反了该合同：

```js
/**
 * @param {HTMLImageElement} img
 * @constructor
 */
var Sprite = function(img) {
    this.img = img;
};

/**
 * @param {CanvasRenderingContext2D} ctx
 */
Sprite.prototype.draw = function(ctx) {
    // ...
};

/**
 * @param {number} x
 * @param {number} y
 * @param {Sprite} sprite
 * @constructor
 */
var Player = function(x, y, sprite) {
    this.x = x;
    this.y = y;
    this.sprite = sprite;
};
```

在给定的示例代码中，您会注意到`Player`和`Sprite`构造函数被注释为`@constructor`。当闭包编译器看到调用这些函数的代码没有使用 new 运算符时，它会推断代码的执行方式与预期不同，并引发编译错误，以便您可以修复错误的代码。此外，如果尝试实例化`Player`，例如，发送到构造函数的值不是一对数字，后跟`Sprite`类的实例，编译器将提醒您，以便您的代码可以得到纠正。

使用闭包编译器的最简单方法是依赖 Grunt 或 Gulp，并安装闭包的等效构建任务。流行的解决方案如下：

```js
// For Grunt users:
npm install grunt-closure-compiler

// If you prefer Gulp:
npm install gulp-closure-compiler

```

# 公平竞争和用户体验

到目前为止，在本章中，我们已经讨论了安全性的许多不同方面，所有这些都旨在为用户提供公平竞争。尽管我们可以尽力保护我们的服务器、知识产权、用户数据和其他玩家，但归根结底，攻击者总是处于优势地位。

特别是在多人游戏中，数十、甚至数百或数千名不同的玩家将同时享受您的游戏，您可能会到达一个点，尝试保护玩家免受自己的侵害不是一个明智的时间或其他资源投资。例如，如果一个孤立的玩家希望通过作弊的方式跳得比游戏允许的更高，或者更改保存游戏以反映额外的生命，那么您最好只让该玩家在自己的客户端上继续进行黑客攻击。只要确保其他玩家不受影响。

从本节以及整个章节中的关键要点是用户体验至关重要。尤其是当多个玩家共享游戏世界寻找快乐时，其中一个玩家只是想找到一种破坏其他人快乐的方式；您必须确保无论发生什么，其他玩家都可以继续游戏。

# 摘要

通过本章，我们结束了关于多人游戏开发的讨论，尽管它涵盖了一个必须从一开始就深入了解的主题。请记住，安全性不能简单地在项目结束时添加；相反，它必须与软件的其余部分一起有意识地构建。

我们看到了基于浏览器的游戏中一些最基本的安全漏洞，以及保护游戏免受这些漏洞的常见方法。我们还讨论了一些任何严肃的游戏都不应该缺少的技术。最后，我们看了如何使用现有的开源工具通过 Node 的 Npm 来实现这些技术。

总之，现在你已经完成了学习 JavaScript 多人游戏开发基础的旅程的最后一关，我想让你知道，尽管这可能很令人兴奋，但你的旅程还没有结束。*谢谢你的阅读，但公主在另一个城堡里！* 现在你必须忙于编写下一个多人游戏，让所有玩家经历充满乐趣、娱乐和实时精彩的旅程。游戏结束！
