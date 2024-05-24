# C++ 游戏开发的程序化内容生成（二）

> 原文：[`zh.annas-archive.org/md5/78a00fe20d9b720cedc79b3376ba4721`](https://zh.annas-archive.org/md5/78a00fe20d9b720cedc79b3376ba4721)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：创建独特和随机的游戏对象

在本章中，我们将使我们的类更加随机。在第三章中，我们涉及了类似的主题，通过给玩家随机的统计数据，所以我们将继续沿着这条路走下去，构建更大、更多功能的程序类。

随机生成游戏物品是为游戏带来多样性和可重玩性的好方法。例如，《无主之地》中的所有武器都是随机生成的；每个箱子和战利品掉落都会包含一个独特的物品。这给游戏带来了一种未知的元素，每次找到一个物品时都不知道它可能是什么。

在本章中，我们将涵盖以下主题：

+   给对象随机精灵

+   为我们的玩家生成随机特质

+   随机分配统计数据

+   程序生成一系列游戏物品

# 创建一个随机的玩家角色

在第三章，“使用 C++数据类型进行 RNG”，我们给了我们的玩家随机的统计数据。让我们继续进一步发展`player`对象。我们将给我们的`player`一个随机的职业，并使用这个来设置一个合适的精灵和统计数据。我们还将给玩家随机的特质，这将增强某些统计数据。

## 选择玩家职业

让我们首先为玩家分配一个随机的职业。第一步是定义一个枚举器，它将定义可能的职业。我们将把这个放在`Util.h`中的其他枚举器中：

```cpp
// Player classes.
enum class PLAYER_CLASS {
  WARRIOR,
  MAGE,
  ARCHER,
  THIEF,
  COUNT
};
```

现在，在`player`类的构造函数中，我们将随机选择其中一个类。为此，我们需要生成一个从 0 到 3 的数字，并将其用作枚举器中的索引。我们还将创建一个变量来保存选择，以防以后使用。

我们将从`Player.h`中声明变量，如下所示：

```cpp
/**
 * The player's class.
 */
PLAYER_CLASS m_class;
```

### 提示

我们不能将这个变量称为“class”，因为它是 C++中的关键字。在命名变量时要牢记关键字，以避免这种冲突

在构造函数中，让我们生成随机索引并设置类如下：

```cpp
// Generate a random class.
m_class = static_cast<PLAYER_CLASS>(std::rand() % stat-ic_cast<int>(PLAYER_CLASS::COUNT));
```

就是这么简单。现在每次创建玩家时，都会选择一个随机的职业，这可以用来实现不同的行为和外观。

## 精灵和纹理概述

在我们开始处理对象的精灵之前，让我们花点时间看看我们的游戏是如何处理精灵和纹理的。您可能已经知道，要在 SFML 中绘制对象，我们需要一个精灵和一个纹理资源。当我们想要改变精灵时，我们实际上只需要改变`sf::sprite`持有引用的`sf::Texture`对象。鉴于此，精灵存储在它们所属的对象中，而纹理存储在单个“静态纹理管理器类”中。

“纹理”是一种昂贵且沉重的资源，因此将它们全部放在一个对象中，并仅通过引用与它们交互，是理想的。这意味着我们不必担心它们的移动或使对象变得沉重。 `TextureManager`类的使用方式如下：

+   要向游戏添加“纹理”，我们静态调用`TextureManager::AddTexture`，并传递我们想要加载的精灵的路径，该函数返回管理器类中纹理的索引。

+   要从`manager`中获取“纹理”，我们静态调用`TextureManager::GetTexture`，将我们想要的“纹理”的`ID`作为唯一参数传递。作为回报，如果存在，我们将得到对“纹理”的引用。

这对我们的游戏意味着，我们不再将“纹理”存储在对象中，而是存储它们的纹理管理器 ID。每当我们想要实际的“纹理”时，我们只需调用先前描述的`TextureManager::GetTexture`函数。

### 提示

“纹理资源管理器”类还做了一些其他聪明的事情，比如避免两次加载相同的纹理。我建议您查看该类，并在自己的游戏中采用相同的方法，以确保资源得到正确处理。

## 设置适当的精灵

现在`player`类已经生成了一个随机类，让我们更新精灵以反映这一点。玩家是有动画的，因此有一个包含在数组中定义的八个纹理 ID 的集合。

目前，玩家加载相同的固定纹理集：

```cpp
// Load textures.
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_UP)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_walk_up.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_DOWN)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_walk_down.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_RIGHT)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_walk_right.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_LEFT)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_walk_left.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_UP)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_idle_up.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_DOWN)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_idle_down.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_RIGHT)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_idle_right.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_LEFT)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_idle_left.png");
```

让我们更新这样，如果我们生成一个战士，我们将加载战士纹理，如果我们加载一个法师，我们将加载法师纹理，依此类推。这可以通过简单地使用玩家的类在`switch`语句中加载适当的纹理来实现。

然而，这将创建大量重复的代码：

```cpp
// Load textures.
switch (m_class)
{
    case PLAYER_CLASS::WARRIOR:
    m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_LEFT)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_walk_left.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_UP)] = TextureManager::AddTexture("../resources/players/warrior/spr_warrior_idle_up.png");
    . . .
    break;

    case PLAYER_CLASS::MAGE:
    . . .
    m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_LEFT)] = TextureManag-er::AddTexture("../resources/players/mage/spr_mage_walk_left.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_UP)] = TextureManag-er::AddTexture("../resources/players/mage/spr_mage_idle_up.png");
    . . .
```

对于每种类别，我们将重复相同的代码，唯一的变化是资源中类别的名称。考虑到这一点，我们可以从更好的角度来处理这个问题，并在运行时生成资源路径。

### 提示

在阅读以下代码之前，请尝试自己实现这个。如果遇到困难，代码总是在这里，你甚至可以想出自己的方法！

我们将声明一个字符串变量，可以保存类的名称，并通过对玩家的类执行`switch`语句来设置这个变量。然后我们可以使用这个变量来加载纹理，而不是固定的类名：

```cpp
std::string className;

// Set class-specific variables.
switch (m_class)
{
case PLAYER_CLASS::WARRIOR:
  className = "warrior";
  break;

case PLAYER_CLASS::MAGE:
  className = "mage";
  break;

case PLAYER_CLASS::ARCHER:
  className = "archer";
  break;

case PLAYER_CLASS::THIEF:
  className = "thief";
  break;
}

// Load textures.
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_UP)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_walk_up.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_DOWN)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_walk_down.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_RIGHT)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_walk_right.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_LEFT)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_walk_left.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_UP)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_idle_up.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_DOWN)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_idle_down.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_RIGHT)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_idle_right.png");
m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_LEFT)] = TextureManager::AddTexture("../resources/players/" + className + "/spr_" + className + "_idle_left.png");
```

现在，每次加载游戏时，玩家将是一个随机类，并且有一个匹配的精灵来显示，如下截图所示。

![设置适当的精灵](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_01.jpg)

现在玩家类已经设置，我们可以更新 UI 和玩家投射物以反映它。为此，我们需要从玩家那里获取玩家类。因此，让我们首先向玩家类添加一个简单的 getter 函数。不要忘记声明：

```cpp
// Returns the player's class.
PLAYER_CLASS Player::GetClass() const
{
 return m_class;
}
```

这些都是简单的改变；我们可以切换玩家的类，并在每种情况下加载正确的精灵，而不是固定的代码。让我们从投射物开始。这个精灵设置在`Game::Initialize`中，现在我们所要做的就是为类选择正确的精灵：

```cpp
// Load the correct projectile texture.
//m_projectileTextureID = TextureManager::AddTexture("../resources/projectiles/spr_sword.png");

switch (m_player.GetClass())
{
case PLAYER_CLASS::ARCHER:
 m_projectileTextureID = TextureManager::AddTexture("../resources/projectiles/spr_arrow.png");
 break;
case PLAYER_CLASS::MAGE:
 m_projectileTextureID = TextureManager::AddTexture("../resources/projectiles/spr_magic_ball.png");
 break;
case PLAYER_CLASS::THIEF:
 m_projectileTextureID = TextureManager::AddTexture("../resources/projectiles/spr_dagger.png");
 break;
case PLAYER_CLASS::WARRIOR:
 m_projectileTextureID = TextureManager::AddTexture("../resources/projectiles/spr_sword.png");
 break;
}
```

现在，让我们继续进行玩家 UI。在屏幕左上角，我们有玩家的统计数据，其中一个精灵显示了玩家。由于类是动态的，我们需要相应地更新这个精灵。这个精灵设置在`Game::LoadUI`中，并且它将以与我们设置投射物的方式相似的方式设置。我们将把这留给你自己完成。

## 增强玩家统计数据

现在玩家有了一个类，我们可以做的另一件事是相应地增强统计数据。我们将在分配玩家的统计点之前给某些值一个初始值。

我们已经有一个`switch`语句，我们用它来加载适当的纹理，所以我们可以添加代码到这里。像往常一样，我们不会硬编码这个值，而是留给随机数神，如下所示：

```cpp
// Set class-specific variables.
switch (m_class)
{
case PLAYER_CLASS::WARRIOR:
 m_strength += std::rand() % 6 + 5;
  className = "warrior";
  break;

case PLAYER_CLASS::MAGE:
 m_defense = std::rand() % 6 + 5;
  className = "mage";
  break;

case PLAYER_CLASS::ARCHER:
 m_dexterity = std::rand() % 6 + 5;
  className = "archer";
  break;

case PLAYER_CLASS::THIEF:
 m_stamina = std::rand() % 6 + 5;
  className = "thief";
  break;
}
```

有了这个，我们可以使某些类更有可能在给定技能中具有更高的统计点，并且通过使用随机数，我们可以在我们可以创建的`player`对象中引入更多的随机性和差异。

## 随机角色特征

游戏中有五个统计数据，即`Attack`，`Defense`，`Strength`，`Dexterity`和`Stamina`。让我们创建影响每个统计数据的特征，以便每个角色都倾向于某些统计数据，因此也倾向于某些游戏风格！这意味着玩家必须改变他们的游戏方式来适应他们生成的每个角色。

我们需要首先定义这些特征，所以让我们创建一个枚举器来做到这一点。我们将在`Util.h`中声明以下内容：

```cpp
// Player traits.
enum class PLAYER_TRAIT {
  ATTACK,
  DEFENSE,
  STRENGTH,
  DEXTERITY,
  STAMINA,
  COUNT
};
```

现在我们需要在`player`类中创建一个变量来存储当前活动的特征。我们将给玩家两个特征，因此将声明一个具有该大小的数组。但是，我们将创建一个静态`const`来定义特征计数，而不是硬编码该值，如下所示：

```cpp
/**
 * The number of traits that the player can have.
 */
static const int PLAYER_TRAIT_COUNT = 2;
```

### 提示

我们总是希望尽可能地使代码灵活。因此，在这种情况下，使用具有适当名称的静态`const`比硬编码的值更可取。

随时可以给玩家更多特征；只需创建一个更大的数组，并根据需要修改代码，我们继续前进。现在，让我们定义将保存特征的变量：

```cpp
/**
 * An array containing the character's traits.
 */
PLAYER_TRAIT m_traits[PLAYER_TRAIT_COUNT];
```

要将特征随机分配给玩家，现在我们需要生成两个随机数，并将它们用作`PLAYER_TRAIT`枚举类型的索引。我们将把这种行为封装在自己的函数中。这样，我们可以在游戏运行时随意改变玩家的特征。

让我们在`Player`类中声明以下函数：

```cpp
/**
 * Chooses 2 random traits for the character.
 */
void SetRandomTraits();
```

我们需要这个函数来生成两个索引，然后在 switch 语句中使用它们来增加适当的状态，就像我们确定`player`类时所做的那样。让我们添加这个，如下所示：

```cpp
// Chooses random traits for the character.
void Player::SetRandomTraits()
{
    // Generate the traits.
    for (int i = 0; i < PLAYER_TRAIT_COUNT; ++i)
    {
        m_traits[i] = static_cast<PLAYER_TRAIT>(std::rand() % static_cast<int>(PLAYER_TRAIT::COUNT));
    }

    // Action the traits.
    for (PLAYER_TRAIT trait : m_traits)
    {
         switch (trait)
        {
            case PLAYER_TRAIT::ATTACK: default:
                m_attack += rand() % 6 + 5;
            break;
            case PLAYER_TRAIT::ATTACK: default:
                m_attack += std::rand() % 6 + 5;
            break;
            case PLAYER_TRAIT::DEFENSE:
                m_defense += std::rand() % 6 + 5;
            break;
            case PLAYER_TRAIT::STRENGTH:
                m_strength += std::rand() % 6 + 5;
            break;
            case PLAYER_TRAIT::DEXTERITY:
                m_dexterity += std::rand() % 6 + 5;
            break;

        case PLAYER_TRAIT::STAMINA:
            m_stamina += std::rand() % 6 + 5;
        break;
        }
    }
}
```

虽然这种方法成功地生成了随机特征，但它有一个很大的缺陷；没有检查以确保生成了两个唯一的特征。我们可以给玩家五个特征，虽然这很不太可能，但我们可以给他们五次相同的特征。本章末尾的一个练习是修改这一点，确保只生成唯一的特征索引。我强烈建议尝试一下。

有了这个函数的编写，现在我们只需要在玩家的构造函数中调用它：

```cpp
// Set random traits.
SetRandomTraits();
```

现在每次创建玩家时，他们将随机选择两个特征。最后一步是在 UI 中绘制玩家的特征。为此，我们需要从玩家那里获取特征并修改状态精灵。

## 返回玩家特征数组

特征存储在数组中，C++不允许我们从函数中返回整个数组。为了解决这个问题，我们需要做一些花哨的事情。因此，让我们快速分支出去，看看我们如何解决这个问题。

首先，在`Player.h`中需要声明以下函数，如下所示：

```cpp
/**
 * Gets the players current traits.
 * @return The players two current traits.
 */
PLAYER_TRAIT* GetTraits();
```

我们将给出以下定义：

```cpp
// Return the players traits.
PLAYER_TRAIT* Player::GetTraits()
{
  return &m_traits[0];
}
```

### 提示

请注意，这个函数意味着玩家特征变量可以被改变。

数组只是顺序存储在内存中的值的集合。以下图表显示了它的外观：

![返回玩家特征数组](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_02.jpg)

考虑到这一点，如果我们返回第一个元素的地址，然后可以通过顺序读取以下内存来找到其余的值。为了证明这一点，看一下以下两行，它们的工作方式相同：

```cpp
m_traits[2] = 1;
GetTraits()[2] = 1;
```

因此，虽然我们不返回完整的数组，但我们返回第一个元素，这就是我们所需要的。现在我们可以以与通常相同的方式访问数组。

## 设置特征精灵

现在剩下的就是在主`Game`类中绘制特征。我们已经在窗口底部绘制了玩家的状态。因此，为了指示被特征增强的状态，我们可以使精灵变大，并切换到其备用纹理。状态精灵在`Game::LoadUI`函数中加载和初始化。

在开始之前，我们需要知道玩家有多少特征。因此，让我们在`player`对象中添加一个快速的`GetTraitCount()`函数来给我们这个信息；不要忘记在 Player.h 中添加声明：

```cpp
// Returns the number of traits the player has.
int Player::GetTraitCount()
{
  return PLAYER_TRAIT_COUNT;
}
```

现在，在`Game::LoadUI`中，一旦我们加载了状态精灵，我们就可以调用这个函数，并构建一个循环来迭代这个次数，如下所示：

```cpp
// Set player traits.
int traitCount = m_player.GetTraitCount();

for (int i = 0; i < traitCount; ++i)
{

}
```

现在，我们需要检查每个特征，并将其精灵比例设置为`1.2f`，使其比邻近的精灵稍大。我们还将切换到其备用纹理，带有白色背景。这已经在项目中设置好了，所以我们需要做的就是以以下方式进行切换：

```cpp
for (int i = 0; i < traitCount; ++i)
{
  switch (m_player.GetTraits()[i])
  {
  case PLAYER_TRAIT::ATTACK:
    m_attackStatSprite->setTexture(TextureManager::GetTexture(m_attackStatTextureIDs[1]));
    m_attackStatSprite->setScale(sf::Vector2f(1.2f, 1.2f));
    break;

  case PLAYER_TRAIT::DEFENSE:
    m_defenseStatSprite->setTexture(TextureManager::GetTexture(m_defenseStatTextureIDs[1]));
    m_defenseStatSprite->setScale(sf::Vector2f(1.2f, 1.2f));
    break;

  case PLAYER_TRAIT::STRENGTH:
    m_strengthStatSprite->setTexture(TextureManager::GetTexture(m_strengthStatTextureIDs[1]));
    m_strengthStatSprite->setScale(sf::Vector2f(1.2f, 1.2f));
    break;

  case PLAYER_TRAIT::DEXTERITY:
    m_dexterityStatSprite->setTexture(TextureManager::GetTexture(m_dexterityStatTextureIDs[1]));
    m_dexterityStatSprite->setScale(sf::Vector2f(1.2f, 1.2f));
    break;

  case PLAYER_TRAIT::STAMINA:
    m_staminaStatSprite->setTexture(TextureManager::GetTexture(m_staminaStatTextureIDs[1]));
    m_staminaStatSprite->setScale(sf::Vector2f(1.2f, 1.2f));
    break;
  }
}
```

现在，如果我们运行游戏，我们可以清楚地看到哪些精灵当前被特征增强，如下截图所示。我们之前已经连接了它们的行为。因此，我们知道这些图标对角色的状态产生了影响。

![设置特征精灵](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_03.jpg)

# 过程生成敌人类

现在玩家已经完全生成，让我们将一些应用到敌人身上。我们目前有两个主要的敌人类，即“史莱姆”和“人形”。 “史莱姆”是一个简单的史莱姆敌人，但我们的“人形”类是为了扩展而存在的。目前，该类加载骷髅的精灵，但让它可以成为多种人形敌人；在我们的情况下，它可以是哥布林或骷髅。

我们本可以为这些敌人制作单独的类，但由于它们的大部分代码都是相同的，这是没有意义的。相反，我们有这个模糊的“人形”类，可以成为人形敌人的形式。我们所需要做的就是改变精灵，以及如果我们希望它们有不同的玩法，我们分配统计数据的方式。从这里我们可以从“单一”类中创建许多不同的敌人。我们很快也会在药水上使用相同的方法！

现在，我们将从`Util.h`中定义一个枚举器，表示不同类型的人形敌人：

```cpp
// Enemy humanoid types.
enum class HUMANOID {
  GOBLIN,
  SKELETON,
  COUNT
};
```

现在，如果我们回想一下`player`构造函数，我们生成了一个类，并对该变量执行了一个开关，以执行依赖于类的行为。我们将在这里使用完全相同的方法。我们将从我们刚刚定义的枚举器中生成一个随机敌人类型，然后相应地设置精灵和统计数据。

在`Humanoid::Humanoid`中，让我们选择一个随机的人形类型，并创建一个字符串来保存敌人的名称，如下所示：

```cpp
// Default constructor.
Humanoid::Humanoid()
{
    // Generate a humanoid type. (Skeleton or Goblin).
    HUMANOID humanoidType = static_cast<HUMANOID>(std::rand() % static_cast<int>(HUMANOID::COUNT));
    std::string enemyName;

    // Set enemy specific variables.
    switch (humanoidType)
    {
        case HUMANOID::GOBLIN:
            enemyName = "goblin";
        break;

        case HUMANOID::SKELETON:
            enemyName = "skeleton";
        break;
    }
    // Load textures.
    m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_UP)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_walk_up.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_DOWN)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_walk_down.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_RIGHT)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_walk_right.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_LEFT)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_walk_left.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_UP)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_idle_up.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_DOWN)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_idle_down.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_RIGHT)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_idle_right.png");
    m_textureIDs[static_cast<int>(ANIMATION_STATE::IDLE_LEFT)] = TextureManager::AddTexture("../resources/enemies/" + enemyName + "/spr_" + enemyName + "_idle_left.png");

    // Set initial sprite.
    SetSprite(TextureManager::GetTexture(m_textureIDs[static_cast<int>(ANIMATION_STATE::WALK_UP)]), false, 8, 12.f);
}
```

完成这些后，如果现在运行游戏，您将看到有哥布林和骷髅敌人从“单一”类中生成，如下截图所示：

![过程生成敌人类](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_04.jpg)

# 程序化物品

现在玩家和敌人都已经处理好了，让我们把注意力转向物品。我们有许多类可以随机分配其成员变量。我们将设置“药水”类的方式与我们设置“人形”类的方式相同，从“单一”类中创建多个不同的对象。

## 随机宝石和心类

我们将从最小的类开始，即“心”和“宝石”。这些都是非常简单的类，目前只有一个硬编码的变量。让我们更新一下，使它们的值在创建时随机生成。由于我们希望每次创建对象时都发生这种情况，我们将把它放在物品的构造函数中。

在`Gem::Gem`中，我们将进行以下更改：

```cpp
// Set the value of the gem.
// m_scoreValue = 50;
m_scoreValue = std::rand() % 100;

```

在`Heart::Heart`中，我们将进行以下更改：

```cpp
// Set health value.
// m_health = 15;
m_health = std::rand() % 11 + 10;

```

如果现在运行游戏，并快速查看一下，您将看到这些物品提供不同的分数和生命值。完美！

![随机宝石和心类](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_05.jpg)

## 随机金类

对于最后两个物品，我们只是生成了一个随机值。对于金物品，我们将进一步进行。我们将使用这个随机值来确定对象应该具有的精灵。

为此，我们将把总金值范围分为三个段。我们将定义一个较低范围，一个较高范围，剩下的就是中间范围。例如，如果我们要生成 0 到 10 之间的金值，我们可以有以下情况：

+   小于 3 的都是小的

+   大于 7 的都是大的

+   其他任何都是中等

通过这样做，我们可以设置与金值匹配的精灵。我们将把这段代码放在构造函数中，因为这是应该在每次创建金对象时调用的代码，我们永远不需要手动调用它的行为：

```cpp
// Default constructor.
Gold::Gold()
{
    // Randomly generate the value of the pickup.
    this->goldValue = std::rand() % 21 + 5;

    // Choose a sprite based on the gold value.
    int textureID;
    if (this->goldValue < 9)
    {
        textureID = TextureManager::AddTexture("../resources/loot/gold/spr_pickup_gold_small.png");
    }
    else if (this->goldValue >= 16)
    {
        textureID = TextureManager::AddTexture("../resources/loot/gold/spr_pickup_gold_large.png");
    }
    else
    {
        textureID = TextureManager::AddTexture("../resources/loot/gold/spr_pickup_gold_medium.png");
    }

    // Set the sprite.
    this->SetSprite(TextureManager::GetTexture(textureID), false, 8, 12.f);

    // Set the item type.
    m_type = ITEM::GOLD;
}
```

您可以看到我们生成了一个随机金值，然后简单地使用了几个`if`语句来定义我们的范围。让我们再次运行游戏，看看金对象。您将看到它们的精灵变化，因此被拾取时的金值也会有所不同：

![随机金类](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_06.jpg)

# 随机药水类

对于最大的类更新，我们将把注意力转向`potion`类。这个类目前有一个固定的精灵，并且不给玩家任何东西。通过`humanoid`类，我们可以生成一个随机类型，并从`单一`类中实质上创建两个不同的敌人。我们将使用相同的方法来处理药水。

## 创建一个随机药水

首先，让我们在`Util.h`中定义一个枚举器，表示所有的药水类型。我们将为每个统计数据创建一个：

```cpp
// Potions.
enum class POTION {
  ATTACK,
  DEFENSE,
  STRENGTH,
  DEXTERITY,
  STAMINA,
  COUNT
};
```

为了节省大量的输入，药水类已经有了每种可能统计数据的成员变量和`getter`函数，我们只需要使用它们。我们将添加的一个是用来保存药水类型的变量，以及一个返回它的函数。当捡起物品时，我们需要这些信息！

让我们在`Potion.h`中声明以下内容：

```cpp
public:
  /**
   * Gets the potion type.
   * @return The potion type.
   */
  POTION GetPotionType() const;

private:
  /**
   * The potion type.
   */
  POTION m_potionType;
```

`GetPotionType`是一个简单的`getter`函数，所以在继续之前让我们快速给它一个主体：

```cpp
// Gets the potion type.
POTION Potion::GetPotionType() const
{
    return m_potionType;
}
```

如果你查看 Potion 的初始化列表，你会注意到它将所有的统计变量都设置为 0。从这一点开始，我们可以选择一个随机类型，并设置它的精灵和相应的统计数据，将其余部分保持在它们的默认值 0，因为我们不会使用它们。

首先，我们将生成一个随机值来表示其类型，并创建一个变量来存储精灵路径。以下代码需要放在`Potion::Potion`中：

```cpp
// The string for the sprite path.
std::string spriteFilePath;

// Set the potion type.
m_potionType = static_cast<POTION>(std::rand() % static_cast<int>(POTION::COUNT));
```

有了选定的类型，我们可以切换这个值，设置适当的统计数据，并给`spriteFilePath`设置适当的资源路径，如下所示：

```cpp
// Set stat modifiers, sprite file path, and item name.
switch (m_potionType)
{
case POTION::ATTACK:
  m_dexterity = std::rand() % 11 + 5;
  spriteFilePath = "../resources/loot/potions/spr_potion_attack.png";
  break;

case POTION::DEFENSE:
  m_dexterity = std::rand() % 11 + 5;
  spriteFilePath = "../resources/loot/potions/spr_potion_defense.png";
  break;

case POTION::STRENGTH:
  m_strength = std::rand() % 11 + 5;
  spriteFilePath = "../resources/loot/potions/spr_potion_strength.png";
  break;

case POTION::DEXTERITY:
  m_dexterity = std::rand() % 11 + 5;
  spriteFilePath = "../resources/loot/potions/spr_potion_dexterity.png";
  break;

case POTION::STAMINA:
  m_stamina = std::rand() % 11 + 5;
  spriteFilePath = "../resources/loot/potions/spr_potion_stamina.png";
  break;
}
```

最后，我们只需要以以下方式设置物品精灵和类型，然后就完成了。请注意，这种类型与药水类型不同：

```cpp
// Load and set sprite.
SetSprite(TextureManager::GetTexture(TextureManager::AddTexture(spriteFilePath)), false, 8, 12.f);

// Set the item type.
m_type = ITEM::POTION;
```

如果我们现在运行游戏，并杀死一些敌人，直到我们得到一个药水掉落，我们应该看到药水类型发生变化。从一个单一类中，我们创建了 5 种药水，运行时创建，提供了增益，也是在运行时生成的。

![创建一个随机药水](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_05_07.jpg)

## 确定药水捡起

现在我们有一个`单一`类，有五种不同的潜在增益，我们需要确定我们正在捡起的药水。这就是`Potion::GetType`函数派上用场的地方。当我们接触到`药水`对象时，我们可以检查`药水`的类型，并使用它来确定我们将调用哪个统计数据获取函数。

例如，如果我们捡起一个`药水`，它的类型是`POTION::ATTACK`，那么我们知道我们需要调用`Potion::GetAttack`函数。物品捡起代码位于`Game::UpdateItems`函数中。在这个函数中，我们检查与对象的碰撞，并检查它是什么类型的物品。

当我们确定我们捡起了一个药水时，我们需要调用`Potion::GetPotionType`函数，但是我们有一个问题。由于我们利用多态性将所有物品存储在单个集合中，此时药水物品的类型是`Item`。为了访问`Potion::GetPotionType`函数，我们需要使用`dynamic_cast`进行转换：

### 提示

如果你不确定为什么我们在这里使用`dynamic_cast`而在其他地方使用`static_cast`，请阅读不同类型的转换。

让我们将这种情况添加到`Game::UpdateItems`中的捡起代码中：

```cpp
case ITEM::POTION:
{
  // Cast to position and get type.
  Potion& potion = dynamic_cast<Potion&>(item);
  POTION potionType = potion.GetPotionType();
}
break;
}
```

我们现在确定了我们捡起了一个`药水`并将该物品转换为`药水`对象。接下来，我们可以检查药水的类型，并调用适当的`getter`函数来获取`药水`值。最后，我们将更新玩家的相应统计数据，如下所示：

```cpp
switch (potionType)
{
case POTION::ATTACK:
  m_player.SetAttack(m_player.GetAttack() + potion.GetAttack());
  break;

case POTION::DEFENSE:
  m_player.SetDefense(m_player.GetDefense() + potion.GetDefense());
  break;

case POTION::STRENGTH:
  m_player.SetStrength(m_player.GetStrength() + potion.GetStrength());
  break;

case POTION::DEXTERITY:
  m_player.SetDexterity(m_player.GetDexterity() + potion.GetDexterity());
  break;

case POTION::STAMINA:
  m_player.SetStamina(m_player.GetStamina() + potion.GetStamina());
  break;
}
```

有了这个药水系统就完成了。从一个`单一`类中，我们创建了五种不同的药水，所有值都是随机生成的。

# 练习

为了帮助你测试本章内容的知识，以下是一些练习题，你应该完成。它们对于本书的其余部分并不是必要的，但是完成它们将帮助你评估所涵盖材料的优势和劣势：

1.  给`player`类添加你自己的特性。项目中包含了一个备用的特性资源，你可以使用。

1.  在生成`player`特性时，我们发现可能会多次给玩家相同的特性。改进`Player::SetRandomTraits`函数，使这种情况不再可能。

1.  我们给玩家和敌人的属性并没有与他们造成或承受多少伤害挂钩。将这些属性挂钩起来，使它们对玩家和敌人产生更大的影响。

# 总结

在本章中，我们看了如何使游戏对象独特和随机化，赋予它们随机属性、精灵和变化。通过这种方法，游戏可以生成的物品种类几乎是无限的。当我们有多个类只有轻微不同时，我们可以设计模糊的类，这些类非常灵活，大大增加了多样性。

在下一章中，我们将加强我们的程序化工作。我们将摆脱简单地随机设置成员变量的方式，尝试创建程序化艺术和图形。我们将为敌人程序化地创建纹理，并改变关卡精灵，为地牢的每一层赋予独特的感觉。


# 第六章：程序生成艺术

游戏的艺术是其定义特征之一。通常是我们首先吸引我们的东西，也是让我们着迷的驱动力之一；出色的美学效果可以走很远。鉴于此，我们希望确保这个领域尽可能丰富、多样和沉浸。

然而，艺术在财务上昂贵且耗时。不仅如此，在硬件层面也很昂贵！游戏纹理可以达到 4K 大小，创建一千个 4K 纹理并将它们存储在传统游戏媒体上并不容易。幸运的是，在创建艺术时可以采用各种程序生成技术来帮助解决其中的一些问题。

在本章中，我们将涵盖以下主题：

+   程序生成如何与艺术结合使用

+   程序生成艺术的优缺点

+   使用 SFML 精灵修改器

+   保存修改后的精灵

+   通过程序创建精灵

# 程序生成如何与艺术结合使用

游戏艺术是程序生成的一个很好的候选对象。手工创建它在开发者投入和硬件层面上都很昂贵，并且可以通过程序进行操纵。然而，像一切事物一样，它有一系列的优点和缺点。因此，在我们开始之前，让我们先来看看它们。

## 使用精灵效果和修改器

程序生成可以与游戏艺术结合的最简单方式可能是通过使用内置函数来操纵现有的精灵和模型。例如，大多数游戏引擎和框架都会提供一些编辑图形的功能，如颜色、透明度和比例修改器。

将这些功能与随机数生成器（RNG）结合使用是开始生成随机游戏艺术的一种简单快速的方法。例如，Simple and Fast Multimedia Library（SFML）提供了改变精灵颜色和大小的功能。即使只使用这些功能，我们也可以在运行时生成各种不同的纹理。如下截图所示：

![使用精灵效果和修改器](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_01.jpg)

## 组合多个纹理

从简单修改现有纹理的方式升级，是将多个纹理组合在一起创建新的纹理。加入一些随机数生成器，你就可以轻松地创建大量的精灵。在本章中，我们将使用这种技术为我们的敌人随机生成盔甲！

我们将从一个基本的敌人精灵开始，随机选择一些盔甲，并将其绘制在原始图像上，以创建一个随机精灵！稍后再详细介绍，但现在先看看它会是什么样子：

![组合多个纹理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_02.jpg)

## 从头开始创建纹理

创建程序纹理的最复杂方式是使用算法从头开始创建它们。诸如 Perlin 噪声之类的算法可以用来创建自然外观的纹理基础，然后可以使用诸如图像乘法之类的技术来创建各种程序纹理。

例如，可以将基本的 Perlin 噪声纹理、白噪声纹理和纯色结合起来创建程序纹理，如下所示：

![从头开始创建纹理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_03.jpg)

采用这种方法，对生成第一和第二个纹理的算法进行更改将导致不同的最终纹理。这种技术可以用来为游戏创建无尽的独特纹理，而不会产生存储问题。

### 提示

这种类型的程序图像创建超出了本书的范围。如果你希望进一步深入了解，请阅读有关纹理合成和 Perlin 噪声等算法的资料。

## 创建复杂的动画

计算能力的增长也催生了程序动画。传统上，动画游戏资源，如角色，会由动画师在 3D 动画软件中制作动画。然后，游戏引擎在运行时加载这个动画例程，并应用于给定的模型以使其移动。

由于计算机现在能够进行比以往更多的计算，程序动画变得越来越受欢迎。现在很多游戏中都使用布娃娃身体，这是程序动画的一个很好的例子。与播放一组固定的动画例程不同，身体的信息，如重量、速度和刚度，被用来计算身体应该处于的位置，以创建逼真和动态的运动。

# 程序生成艺术的好处

游戏艺术的程序生成为我们开发人员和玩家带来了一系列好处。从其多功能性，到成本效益和节省时间，让我们来看看其中的一些好处。

## 多功能性

程序生成游戏艺术的主要好处是多功能性。游戏艺术的制作成本很高，因此对于给定项目来说，会有一定的限制。虽然让艺术家为我们的游戏创建成千上万种纹理会很好，但这是不可行的。相反，我们可以创建一些资源，利用程序技术将这些资源转化为成千上万种可能的纹理，并为游戏带来多样性和丰富性。

## 廉价生产

在前面的观点上进行扩展，由于我们不必支付艺术家手工创建所有这些纹理，程序生成为我们节省了时间和金钱。在本章中，我们将要处理的示例是为我们的敌人提供随机护甲。将有三种类型的护甲，每种有三个等级，敌人所拥有的护甲的组合也将是随机的。可能的组合数量是巨大的，让艺术家手工创建它们将是昂贵的。

## 它需要很少的存储空间

继续以给予敌人护甲的例子，即使我们可以让艺术家手工制作所有的精灵，它们将如何被存储？虽然对于在线游戏来说这不是太大的问题，因为游戏和下载大小通常没有限制，但是那些需要传统媒体（如光盘）发行的游戏必须明智地利用空间。在这方面，纹理是一种昂贵的资源。因此，创建一些资源并通过程序从中创建纹理可以缓解这些问题。

# 程序生成艺术的缺点

好处与坏处并存，程序生成的艺术也不例外。虽然它灵活并节省空间，但它也有一些缺点。

## 缺乏控制

第一个缺点是应用程序不可知的，这是程序生成的一个整体缺点；它带来的失控。如果你通过程序生成艺术，你会失去一个熟练艺术家所能赋予的触感。内容可能缺乏特色，由于是确定性过程的结果，而不是创造性的过程，可能会感觉非常僵硬。一个好的程序算法可以在一定程度上缓解这个问题，但很难生成感觉和看起来像一个有才华的艺术家所创作的自然内容。

## 可重复性

程序生成艺术的另一个潜在问题是，事物可能会显得非常重复和不自然。内容将通过算法产生，输出的变化是使用术语的差异的结果。鉴于此，每个算法都有可能产生的内容范围。如果算法的操作范围太小，纹理将会重复，并且可能会感到不自然和重复使用，尽管程序生成被用来缓解这个问题！这完全取决于算法的质量和使用方式。

## 性能重

程序生成艺术通常涉及大量的读取和复制纹理，这些通常是昂贵的操作，特别是如果你使用高分辨率纹理。以敌人盔甲为例，如果我们手动创建精灵，我们只需要加载纹理，这是一个单一的操作。如果我们程序生成一个精灵，我们必须加载每个组件，编辑它们，并重新渲染它们以创建一个新的纹理。

# 使用 SFML 精灵修改器

现在我们已经确定了程序生成艺术的一些优点和缺点，开始吧！我们将首先看一下的天真方法是简单地使用`sprite`修改器，如`color`和`alpha`来改变现有的精灵。使用这种方法，我们将使用 SFML 提供的内置精灵修改器。大多数引擎和框架都会有类似的函数，如果没有，你也可以自己创建！

## SFML 中颜色的工作原理

让我们从最简单的程序生成精灵的方法开始，在运行时为它生成一个独特的颜色。在 SFML 中，颜色简单地是四个`uint8`值的集合，每个颜色通道一个，还有一个 alpha 通道：

```cpp
sf::Color::Color  (
Uint8   red,
Uint8   green,
Uint8   blue,
Uint8   alpha = 255
)
```

SFML 中的每个`sf::Sprite`都有一个`sf::Color`成员变量。这个颜色值与纹理中像素的颜色值相乘，得到最终的颜色。下图演示了这一点：

![SFML 中颜色的工作原理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_04.jpg)

在上图中，我们可以看到最左边的原始图像。此外，我们还可以看到精灵设置了各种颜色时的结果图像。

### 提示

为了获得最佳效果，最好从单色灰色基础纹理开始，以便颜色调制到达正确的颜色。

`sf::Color`类型还有一个*alpha*值，用于确定对象的不透明度。alpha 通道越低，对象就越透明。通过这个值，你可以改变对象的不透明度，如下图所示：

![SFML 中颜色的工作原理](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_05.jpg)

了解了 SFML 如何处理颜色，让我们通过为史莱姆角色生成一个随机精灵，并在程序中设置它的颜色和 alpha 值来将其付诸实践。

### 提示

要了解更多关于 SFML 如何处理颜色的信息，请阅读[`www.sfml-dev.org/learn.php`](http://www.sfml-dev.org/learn.php)上找到的 SFML 文档。要了解更多详细信息，请前往 SFML 使用的图形 API OpenGL 文档。

## 创建随机颜色的精灵

在 SFML 中，精灵对象有一个名为`setColor()`的成员函数。这个函数接受一个`sf::Color`对象，并将其设置为在绘制时与精灵纹理相乘的值。我们知道`sf::Color`本质上只是四个`uint8`值，每个值的范围是 0 到 255。鉴于此，要生成一个随机颜色，我们可以为这些颜色通道生成随机值，或者随机选择 SFML 预定义颜色中的一个。

史莱姆敌人是一个很好的选择，因为它在许多颜色下都会看起来很棒，而基础精灵是一种沉闷的灰色。将颜色与这个精灵相乘将起到很好的效果。当我们设置史莱姆精灵时，我们将使用这两种方法随机给它一个颜色。让我们从选择预定义颜色开始。

### 随机选择预设颜色

SFML 带有以下预定义颜色：

```cpp
sf::Color black       = sf::Color::Black;
sf::Color white       = sf::Color::White;
sf::Color red         = sf::Color::Red;
sf::Color green       = sf::Color::Green;
sf::Color blue        = sf::Color::Blue;
sf::Color yellow      = sf::Color::Yellow;
sf::Color magenta     = sf::Color::Magenta;
sf::Color cyan        = sf::Color::Cyan;
sf::Color transparent = sf::Color::Transparent;
```

这些在`Color.hpp`中定义，并涵盖了最受欢迎的颜色。首先的问题是我们需要一种随机选择的方法。为此，我们可以创建一个匹配颜色值的枚举器，生成一个随机索引，然后使用它来将枚举器值与匹配的预定义颜色相匹配。当我们看代码时，这将变得更清晰。

我们将首先在`Util.h`文件中添加以下枚举器定义：

```cpp
// Colors provided by SFML.
enum class COLOR {
  BLACK,
  WHITE,
  RED,
  GREEN,
  BLUE,
  YELLOW,
  MAGENTA,
  CYAN,
  TRANSPARENT,
  COUNT
};
```

对于每个预定义颜色，我们已经为`enum`添加了相应的值，确保它以`COUNT`结尾。有了这个定义，我们只需要计算 0 到`COLOR::COUNT`之间的数字，然后在`switch`语句中使用它。这是我们现在已经使用了几次的方法，所以我们应该对它很熟悉。

跳转到史莱姆敌人的构造函数，我们将从生成一个随机索引开始：

```cpp
int colorIndex = std::rand() % static_cast<int>(COLOR::COUNT);
```

现在，我们只需要切换`colorIndex`值并设置相应的颜色：

```cpp
switch (colorIndex)
{
case static_cast<int>(COLOR::BLACK):
  m_sprite.setColor(sf::Color::Black);
  break;

case static_cast<int>(COLOR::BLUE):
  m_sprite.setColor(sf::Color::Blue);
  break;
```

这应该对我们定义的每个枚举值进行继续。现在，你会看到每个生成到游戏中的史莱姆敌人都有不同的预定义颜色：

随机选择预设颜色

### 随机生成颜色

第二个选项，给了我们更多的控制权，就是随机生成我们自己的颜色。这种方法给了我们更广泛的可能性范围，同时也让我们可以访问 alpha 通道；然而，我们失去了一些控制。当从预定义颜色中选择时，我们知道我们最终会得到一种令人愉悦的颜色，这是我们无法保证当为每个通道生成我们自己的值时。尽管如此，让我们看看我们将如何做。

我们知道`sf:color`有四个通道（r、g、b 和 a），每个值都在 0 到 255 之间。为了生成随机颜色，我们需要为 r、g 和 b 通道生成值；a 是 alpha 通道，它将允许我们改变精灵的不透明度。

首先，我们将定义变量并为 r、g 和 b 通道生成随机值，如下所示：

```cpp
int r, g, b, a;

r = std::rand() % 256;
g = std::rand() % 256;
b = std::rand() % 256;
```

对于 alpha 通道，我们希望在数字生成方面更加精确。alpha 值为 0 太低了；我们几乎看不到精灵。因此，我们将生成一个在 100 到 255 范围内的数字，如下所示：

```cpp
a = std::rand() % 156 + 100;
```

现在我们有了这些值，我们需要创建一个`sf::color`对象，将`r`、`g`、`b`和`a`值传递给`color`构造函数：

```cpp
sf::Color color(r, g, b, a);
```

最后一步是调用`sf::sprite::setColor()`，传递新的颜色。完整的代码如下，应该放在史莱姆敌人的构造函数中：

```cpp
// Choose the random sprite color and set it.
int r, g, b, a;

r = std::rand() % 256;
g = std::rand() % 256;
b = std::rand() % 256;
a = std::rand() % 156 + 100;
sf::Color color(r, g, b, 255);

m_sprite.setColor(color);
```

现在，如果我们运行游戏，我们应该会得到三个非常不同颜色的史莱姆，每个都有不同程度的不透明度，如下截图所示：

随机生成颜色

## 生成随机颜色

我们将要玩耍的最后一个精灵修改器是缩放。使用`sf::Sprite::setScale()`函数，我们可以设置精灵的水平和垂直缩放。默认缩放为 1，所以如果我们使用值为 2 进行缩放，精灵将变大一倍。同样，如果我们设置为 0.5 的缩放，它将变小一半。鉴于此，我们需要生成接近 1 的浮点数。0.5 到 1.5 的范围应该给我们足够的大小差异！

所以，我们需要生成一个浮点数，但`std::rand()`函数只会生成一个整数值。别担心！我们可以使用一个简单的技巧来得到一个浮点数！我们只需要生成一个 5 到 15 之间的数字，然后除以 10 得到浮点值：

```cpp
float scale;
scale = (std::rand() % 11 + 5) / 10.f;
```

现在随机比例值已经生成，我们现在只需要调用`sf::sprite::setScale()`函数，并使用`scale`变量作为缩放值。完整的代码如下：

```cpp
// Generate a random scale between 0.5 and 1.5 and set it.
float scale;
scale = (std::rand() % 11 + 5) / 10.f;

m_sprite.setScale(sf::Vector2f(scale, scale));
```

运行游戏后，你会看到史莱姆敌人有不同的颜色，它们的大小也不同：

生成随机大小的精灵

# 保存修改后的精灵

在我们的游戏中，每次运行游戏时，我们都将生成新的精灵。我们希望每次运行都是独一无二的，所以一旦我们生成了一个精灵并使用它，我们就可以让它离开。然而有时，你可能想保留一个精灵。例如，你可能想创建一个随机的 NPC 并在整个游戏中保持相同的角色。

到目前为止，我们用来创建图像的两种数据类型是`sf::Sprite`和`sf::Texture`。这些类让我们通过一组预定义的成员函数与图像交互。它非常适用于标准绘图和简单的图像操作，但我们无法访问原始图像信息。这就是`sf::Image`发挥作用的地方！

## 将纹理传递到图像

`Sf::Image`是一个用于加载、操作和保存图像的类。与其他数据类型不同，`sf::Image`为我们提供了原始图像数据，允许我们与图像中的每个像素交互。我们稍后将使用更多这方面的功能，但现在，我们对`sf::Image::saveToFile`函数感兴趣。

通过这个函数，我们可以将图像保存到文件；我们只需要将纹理放入图像中。幸运的是，有一个函数可以做到这一点！`sf::Texture`类有一个名为`copyToImage`的函数，它将纹理中的原始图像数据复制到图像中。所以，我们应该能够将纹理复制到图像并保存它，对吗？好吧，让我们试试看。

在`Slime::Slime`中，在我们修改了精灵之后，让我们添加以下调试代码：

```cpp
// Save the sprite to file.
sf::Image img = m_sprite.getTexture()->copyToImage();
img.saveToFile("../resources/test.png");
```

如果你看一下我们创建的文件并将其与原始图像进行比较，你会发现有些奇怪的地方：

![保存图像到文件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_10.jpg)

我们对精灵所做的修改不会编辑纹理。相反，每次绘制对象时都会进行修改。当我们像这样输出纹理时，我们只是输出了放入的相同精灵！为了保存通过精灵修改所做的更改，我们还需要利用`sf::RenderTexture`类。

## 绘制到 RenderTexture 类

由于精灵修改不会应用到纹理上，我们需要以某种方式捕捉一旦渲染完成的精灵。再次，SFML 通过其`sf::RenderTexture`类来解决这个问题。这个类允许我们渲染到纹理而不是屏幕，解决了修改不会应用到纹理上的问题。

首先，我们需要创建一个`sf::RenderTexture`对象。为此，我们需要知道我们将要绘制的区域的大小，并且在这里有一些需要记住的事情。我们正在改变对象的大小。因此，如果我们只是获取纹理的大小，它要么太大要么太小。相反，我们需要获取纹理的大小并将其乘以我们应用于精灵的相同比例值。

让我们写一些代码来使事情更清晰。我们将首先创建`sf::RenderTarget`对象，如下所示：

```cpp
// Create a RenderTarget.
sf::RenderTexture texture;

int textureWidth(m_sprite.getTexture()->getSize().x);
int textureHeight(m_sprite.getTexture()->getSize().y);
texture.create(textureWidth * scale, textureHeight * scale);
```

正如你所看到的，我们将获取纹理的大小并将其乘以我们修改精灵的相同比例。

最后，我们将对象绘制到渲染视图中，如下所示：

```cpp
// Draw the sprite to our RenderTexture.
texture.draw(m_sprite);
```

## 保存图像到文件

从这一点开始，代码与我们的第一次尝试相同，但有一点修改。因为精灵是动画的，我们改变了它的原点和`textureRect`属性，以将其切割成子部分以便动画角色。为了看到整个纹理，这需要恢复。此外，当我们调用`sf::Texture::copyToImage`时，精灵会垂直翻转。在保存文件之前，我们需要将其翻转回来。

以下是用于保存修改后 slime 纹理的完整代码示例：

```cpp
// Create a RenderTarget.
sf::RenderTexture texture;

int textureWidth(m_sprite.getTexture()->getSize().x);
int textureHeight(m_sprite.getTexture()->getSize().y);
texture.create(textureWidth * scale, textureHeight * scale);

// Revert changes the animation made.
m_sprite.setOrigin(sf::Vector2f(0.f, 0.f));
m_sprite.setTextureRect(sf::IntRect(0, 0, textureWidth, textureHeight));

// Draw the sprite to our RenderTexture.
texture.draw(m_sprite);

// Copy the texture to an image and flip it.
sf::Image img = texture.getTexture().copyToImage();
img.flipVertically();

// Save the sprite to file.
img.saveToFile("../resources/test.png");
```

### 提示

完成后不要忘记删除这段代码，因为保存文件很昂贵，而且会搞乱动画！

现在，如果你运行游戏并查看文件，你会看到我们所做的修改。

![将纹理传递到图像](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_09.jpg)

# 以程序方式创建敌人精灵

拥有渲染到`sf::RenderTexture`并存储结果的能力打开了无限的可能性。其中之一是组合多个精灵以创建新的、更多功能的精灵。我们可以多次绘制到`sf::RenderTexture`类，并且精灵将重叠。这是一种非常有用的技术，可以用来生成大量的精灵变化，而无需进行大量工作。这在以下截图中显示：

![创建敌人精灵的过程](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_11.jpg)

使用这种方法，我们将为我们的敌人创建随机盔甲。我们将有三件盔甲；头部、躯干和腿部。对于每个部分，我们还将有三种变化；青铜、银和金。这本身就给我们提供了大量可能的组合。然后，让我们考虑到我们需要这个对于每个角色，我们有两个，每个角色有八个精灵。这是一个巨大的纹理数量。完全不可能手动创建所有这些。

## 将精灵分解为组件

我们将创建的盔甲精灵将直接放在默认的敌人动画上。在这里需要考虑的最重要的事情是，当它们在彼此上方绘制时，它们的大小和位置将对齐。

当创建一个`sf::RenderTexture`类时，我们定义一个大小。然后绘制到它的一切将相对于这个区域的左上角定位。如果我们的精灵大小不同，当我们开始绘制时，它们将不对齐。以下示例已经将它们的背景变暗，以便我们可以看到这一点。在第一个示例中，精灵已经被裁剪，我们可以看到这使它们在彼此上方叠放时不对齐：

![将精灵分解为组件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_12.jpg)

在第二个示例中，精灵的大小相同，并且都相对于它们将被绘制在其上的精灵定位。因此，它们将很好地对齐：

![将精灵分解为组件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_13.jpg)

我们将为每个敌人创建盔甲，因此对于每个敌人动画，我们需要创建一个匹配的盔甲精灵。这已经完成了以节省时间，您会注意到这些精灵只有灰色版本。为了节省更多时间，我们将使用精灵修改器来改变颜色。

这是骷髅行走精灵条上的盔甲叠加精灵的示例：

![将精灵分解为组件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_14.jpg)

## 绘制设置

在我们编写任何关于生成盔甲的代码之前，我们需要改变`Humanoid`类处理其纹理的方式。由于我们将创建的纹理对于类的每个实例都是独一无二的，并且只会被使用一次，所以没有必要将**Texture**管理器填满它们。相反，我们将创建自己的纹理数组，并覆盖默认的绘制行为以使用新的纹理！

我们将从在`Humanoid.h`中定义纹理数组开始，如下所示：

```cpp
  /**
   * An array of modified textures.
   */
  sf::Texture m_textures[static_cast<int>(ANIMATION_STATE::COUNT)];
```

现在，在`Humanoid`构造函数中，我们需要用默认的敌人纹理填充这个数组。这是因为我们将覆盖默认的绘制行为以使用修改后的精灵数组覆盖默认的精灵。只有在生成盔甲时才会创建修改后的精灵。因此，我们需要确保我们有默认的精灵作为后备。我们将用默认精灵填充数组，然后如果我们生成盔甲，就覆盖它们。

将以下代码添加到`Humanoid::Humanoid`中。然后，我们的准备工作就完成了，我们可以开始了：

```cpp
// Copy textures.
for (int i = 0; i < static_cast<int>(ANIMATION_STATE::COUNT); ++i)
{
  m_textures[i] = TextureManager::GetTexture(m_textureIDs[i]);
}
```

## 随机选择精灵组件

我们的敌人可以拥有三种可能的盔甲部件；头部、躯干和腿部，我们希望我们的敌人拥有这些类型的混合。因此，让我们给每个敌人一次生成这些部件的机会。这意味着拥有更多装备的敌人生成的可能性更小，这正是我们想要的；一个全副武装的骷髅应该是一个罕见的生成！

### 提示

不要忘记游戏机制的平衡。在创建程序化系统时，很容易专注于技术，而忽视平衡。设计系统时一定要牢记这一点。您可以访问[`www.paranoidproductions.com/`](http://www.paranoidproductions.com/)，这里包含了很多关于这个主题的信息。

让我们开始创建一个函数，将所有这些行为放进去。护甲是设计用来覆盖哥布林和骷髅精灵的。因此，我们可以将它放在`Humanoid`类中，并为两种变体生成护甲！

让我们声明`Humanoid::GenerateArmor`函数，如下所示：

```cpp
private:
 /**
  * Generates random armor for the humanoid.
  */
void GenerateArmor();
```

我们需要做的第一件事是创建我们将要绘制的`sf::RenderTexture`对象。我们将为每个精灵使用两个纹理：一个用于护甲，一个用于最终图像。我们将首先绘制护甲，然后将其绘制在默认敌人精灵上，以创建最终纹理。

让我们给新函数一个主体并设置对象：

```cpp
// Randomly generates armor.
void Humanoid::GenerateArmor()
{
    // Create arrays of textures.
    const int textureCount = static_cast<int>(ANIMATION_STATE::COUNT);
    sf::RenderTexture armorTextures[textureCount];
    sf::RenderTexture finalTextures[textureCount];
    sf::Image renderImage;
    // Setup all render textures.
    for (int i = 0; i < static_cast<int>(ANIMATION_STATE::COUNT); ++i)
    {
        sf::Vector2u textureSize = m_textures[i].getSize();
        armorTextures[i].create(textureSize.x, textureSize.y);
        finalTextures[i].create(textureSize.x, textureSize.y);
    }
```

现在我们可以添加代码来选择敌人将拥有哪些护甲。我们说过每个物品都有 20%的生成几率。因此，我们需要生成一个从 0 到 4（包括 4）的数字。这样一来，结果为 0 的概率就是 20%。因此，我们可以使用这个来确定是否应该生成该护甲物品：

```cpp
// Create variables to determine what armor be created.
int hasHelmet(0), hasTorso(0), hasLegs(0);

hasHelmet = std::rand() % 5;
hasTorso = std::rand() % 5;
hasLegs = std::rand() % 5;

// Spawn helmet.
if (hasHelmet == 0)
{
}

// spawn torso.
if (hasTorso == 0)
{
}

// spawn legs.
if (hasLegs == 0)
{
}
```

现在我们已经随机选择了敌人将拥有的护甲物品（如果有的话），我们可以将注意力转向通过编辑精灵来创建不同的护甲等级。这需要大量的代码来实现。因此，从这一点开始，我们将只关注头盔选项。

## 加载默认护甲纹理

首先，我们需要加载默认的护甲纹理。每个敌人有八种可能的动画状态，这意味着我们需要加载所有八种头盔对应的纹理。我们将以与在构造函数中加载默认精灵类似的方式来做，创建一个纹理数组，并使用动画状态的枚举作为索引，如下所示：

```cpp
// Spawn helmet.
if (hasHelmet == 0)
{
  // Load the default helmet textures.
  int defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::COUNT)];

  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::WALK_UP)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_walk_front.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::WALK_DOWN)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_walk_front.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::WALK_RIGHT)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_walk_side.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::WALK_LEFT)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_walk_side.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::IDLE_UP)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_idle_front.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::IDLE_DOWN)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_idle_front.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::IDLE_RIGHT)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_idle_side.png");
  defaultHelmetTextureIDs[static_cast<int>(ANIMATION_STATE::IDLE_LEFT)] = TextureManager::AddTexture("../resources/armor/helmet/spr_helmet_idle_side.png");
```

默认精灵加载完毕后，我们现在可以选择它们属于哪种护甲等级，因此，我们需要对它们应用什么颜色进行选择。

## 选择护甲等级

每种类型将有三种护甲等级，即黄金、白银和青铜。因此，我们需要决定使用哪种等级。我们可以采取一种天真的方法，从 0 到 2 生成一个数字，但这并不理想。每个等级的生成机会都是相同的，即 33%。

让我们在选择护甲等级时更加狡猾，使白银比青铜更加稀有，黄金更加稀有。为了做到这一点，我们仍然会使用`std::rand()`函数，但我们会更加聪明地使用结果。首先，我们需要决定每种生成的可能性。假设我们希望其中 50%是青铜，35%是白银，15%是黄金。

这些百分比看起来不错，很好处理，因为它们总和为 100。为了复制它们的机会，我们需要生成一个从 1 到 100 的数字，并且我们可以用它来获得期望的百分比：

+   我们有 50%的机会生成一个介于 1 到 50 之间的数字，因为它代表了总可能范围的一半（50/100）

+   我们有 35%的机会生成一个在 51 到 85 范围内的数字，因为这个范围包括了 100 个可能值中的 35 个（35/100）

+   最后，我们有 15%的机会生成一个在 86 到 100 范围内的数字，因为这个范围包括了 100 个可能值中的 15 个（15/100）

让我们将以下代码添加到我们的函数中，继续从上一段代码加载默认纹理：

```cpp
// Generate random number to determine tier.
sf::Color tierColor;
int tierValue = std::rand() % 100 + 1;

// Select which tier armor should be created.
if (tierValue < 51)
{
    tierColor = sf::Color(110, 55, 28, 255); // Bronze.
}
else if (tierValue < 86)
{
    tierColor = sf::Color(209, 208, 201, 255); // Silver.
}
else
{
    tierColor = sf::Color(229, 192, 21, 255); // Gold.
}
```

### 注意

我们使用了`std::rand() % 100 + 1`，而不是`std::rand() % 100`。虽然它们在技术上做的是一样的事情，但第一个生成了一个从 1 到 100 的数字，而后一个生成了一个从 0 到 99 的数字。第一个使我们更容易处理。

我们创建了一个简单的`if`语句，定义了我们之前确定的每个范围。然而，当我们来到金色的`if`语句时，就没有必要了，因为我们已经定义了其他范围。因此，我们现在知道剩下的任何东西都在 86 到 100 的范围内。因此，我们可以简单地使用一个`else`语句，节省了一个评估。

在这个阶段，我们已经随机选择了一个头盔，加载了默认精灵，并选择了一个阶级。

## 渲染盔甲纹理

下一步是编辑盔甲纹理并将其覆盖在默认敌人纹理上。目前，每种盔甲类型我们只有一个灰色精灵。我们需要使用本章前面学到的精灵修改技巧来创建青铜和金色版本。我们可以将灰色保留为银色！

完成此操作所需的流程如下：

+   加载默认头盔纹理

+   使用我们之前设置的`tierColor`变量编辑颜色

+   在`armorTextures`数组中绘制修改后的盔甲纹理

我们需要对敌人的每个动画都这样做。因此，我们将`armorTextures`数组封装在一个`for`循环中，迭代`ANIMATION_STATE`枚举的每个值，如下所示：

```cpp
// Render helmet to armor texture.
for (int i = 0; i < static_cast<int>(ANIMATION_STATE::COUNT); ++i)
{
  // Load the default helmet texture and set its color.
  sf::Sprite tempSprite;
  tempSprite.setTexture(TextureManager::GetTexture(defaultHelmetTextureIDs[i]));
  tempSprite.setColor(tierColor);

  // Flip the texture vertically.
  sf::Vector2u size = armorTextures[i].getTexture().getSize();
  tempSprite.setTextureRect(sf::IntRect(0, size.y, size.x, -size.y));

  // Draw the texture.
  armorTextures[i].draw(tempSprite);
}}
```

`armorTextures`数组现在包含所有头盔精灵，并且它们的颜色已经设置为随机的阶级值。现在我们需要对躯干和腿做完全相同的事情，再次绘制相同的`armorTextures`数组，以便我们可以构建盔甲纹理。这留作本章末尾的练习。现在，让我们看看如何将这些组合在一起创建最终纹理。

## 渲染最终纹理

现在盔甲纹理已经创建，我们需要将它们渲染在默认敌人纹理的上方，以创建最终图像。我们在构造函数中创建了所有默认纹理的副本，所以我们只需要在上面绘制我们新创建的盔甲纹理，然后保存为最终纹理。需要记住的一件事是`sf::Texture::copyToImage`函数会垂直翻转图像。因此，在保存最终版本之前，我们需要将其翻转回来。

让我们添加这最后一部分代码。这段代码需要放在所有盔甲已生成的后面，因此将是`Humanoid::GenerateArmor`函数中的最后一块代码：

```cpp
// Create the final render texture.
for (int i = 0; i < static_cast<int>(ANIMATION_STATE::COUNT); ++i)
{
    sf::Sprite baseSprite, armorSprite;

    // Draw the default texture.
    baseSprite.setTexture(m_textures[i]);
    finalTextures[i].draw(baseSprite);

    // Draw armor on top.
    armorSprite.setTexture(armorTextures[i].getTexture());
    finalTextures[i].draw(armorSprite);

    // Flip the texture vertically.
    sf::Image img = finalTextures[i].getTexture().copyToImage();
    img.flipVertically();

    // Store the resulting texture.
    m_textures[i].loadFromImage(img);
}
```

现在这个函数已经完成，剩下的就是在我们的构造函数末尾调用它：

```cpp
    . . .
    // Copy textures.
    for (int i = 0; i < static_cast<int>(ANIMATION_STATE::COUNT); ++i)
    {
        m_textures[i] = TextureManager::GetTexture(m_textureIDs[i]);
    }

    // Generate armor.
    GenerateArmor();
}
```

## 覆盖默认绘制行为

我们对象的动画代码位于基类`Object`中。当纹理需要更新时，它会去`m_textureIDs`变量中获取正确的纹理，从`TextureManager`类中。由于我们已经创建了自己的纹理并将它们存储在新的`m_textures`数组中，我们需要覆盖这个默认行为以提供我们自己的纹理。

首先，我们需要通过在`Humanoid.h`中添加以下声明来覆盖更新函数：

```cpp
/**
* Overrides the update event of enemy.
* @param timeDelta The time that has elapsed since the last update.
*/
void Update(float timeDelta) override;
```

我们仍然需要调用父类的实现，因为那里是动画逻辑所在。但是，一旦完成了这一点，我们需要在绘制之前提供我们自己的纹理。幸运的是，这很容易做到：

```cpp
// Overrides the update event of enemy.
void Humanoid::Update(float timeDelta)
{
    // Call parent functionality.
    Enemy::Update(timeDelta);

    // Update the texture with our custom textures.
    m_sprite.setTexture(m_textures[m_currentTextureIndex]);
}
```

## 调试和测试

在运行游戏之前，让我们添加一些调试代码来看看我们的工作。之前，我们介绍了如何将纹理保存为图像文件。所以，让我们在这里使用它来保存我们将创建的所有程序精灵。

让我们使用以下代码更新创建最终纹理的循环：

```cpp
// Save the texture to disk.
if ((hasHelmet == 0) || (hasTorso == 0) || (hasLegs == 0))
{
  std::stringstream stream;
  stream << "../resources/test_" << i << ".png";
  img.saveToFile(stream.str());
}
```

这段代码所做的一切就是在生成一件盔甲时将纹理保存到资源文件夹中。如果你运行游戏几次，记住每个骷髅只有 20%的几率调用这段代码，并前往`resources`文件夹，你会看到以下精灵：

![调试和测试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_15.jpg)

这些就是程序生成的精灵！在我的例子中，它是一个骷髅，带有一个我们不必绘制的随机层级的随机一部分盔甲。我们绘制了组成部分，进行了一些程序编辑，并以编程方式将它们组合在一起！

好了，经过这一切，是时候测试代码了。如果一切顺利，当你运行游戏时，你应该会看到一些带头盔的骷髅和哥布林！请记住，每个敌人只有 20%的几率戴着头盔。如果你运气不好，可能需要运行几次游戏才能看到它：

![调试和测试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_16.jpg)

在继续之前，您可以删除我们刚刚添加的用于保存精灵的调试代码。这纯粹是为了调试目的。本章末尾的练习之一是完成代码，并为躯干和腿部盔甲选项添加相同的行为，但请随意进一步进行。实验！

# 编辑游戏瓦片

我们将要看的最终系统将为本书后面要介绍的内容奠定基础。我们将创建一个系统，使地牢的每一层都成为一个独特的环境，实现我们对游戏瓦片的精灵修改的了解。

游戏的目标是尽可能通过尽可能多的楼层，获得尽可能高的分数。在第九章中，*程序生成地牢*，我们将看看如何程序生成地牢，并且在每五层之后，我们将改变主题。让我们创建一个函数，以后在书中使用它来完成这个目标。

解决这个问题的最佳方法是向`Level`对象添加一个函数，设置所有瓦片精灵的颜色。这将是一个公共函数，因为我们将从主游戏类中调用它。

让我们从在`Level`头文件中定义`sf::color`函数开始，如下所示：

```cpp
public:
  /**
   * Sets the overlay color of the level tiles.
   * @param tileColor The new tile overlay color
   */
  void SetColor(sf::Color tileColor);
```

这个函数的定义非常简单。它只是迭代网格中的所有精灵，将它们的颜色设置为传递的参数：

```cpp
// Sets the overlay color of the level tiles.
void Level::SetColor(sf::Color tileColor)
{
  for (int i = 0; i < GRID_WIDTH; ++i)
  {
    for (int j = 0; j < GRID_HEIGHT; ++j)
    {
      m_grid[i][j].sprite.setColor(tileColor);
    }
  }
}
```

有了这个，我们实际上已经完成了。就是这样！我们将在本章后面使用这个函数，但让我们在这里测试一下。我们在`Game.cpp`中初始化`Level`对象，所以一旦我们加载了纹理，我们就可以调用`Level::SetColor`函数，并设置关卡的主题。

让我们用以下测试代码更新`Game::Initialize`函数：

```cpp
// Set the color of the tiles
m_level.SetColor(sf::Color::Magenta);
```

有了这个，我们可以看到一旦我们正确实现了功能，关卡会是什么样子。让我们运行游戏，看看会发生什么：

![编辑游戏瓦片](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_06_17.jpg)

`Level`瓦片现在都有一个应用于构成环境的所有精灵的环境颜色，这样我们就可以为我们的关卡创建独特的外观和感觉。就像我之前提到的，我们将在以后以编程方式生成随机关卡时使用这个系统。现在，我们可以删除调试代码，坐等系统准备好使用！

# 练习

为了帮助你测试本章内容的知识，这里有一些练习，你应该通过它们进行练习。它们对于本书的其余部分并不是必要的，但通过它们的练习，可以帮助你评估自己在所涵盖材料中的优势和劣势：

1.  给哥布林敌人一个稍微随机的颜色和比例，每次生成一个。

1.  通过完成躯干和腿部盔甲的条件，完成为人形生物程序生成盔甲的代码。

1.  尝试以更简洁的方式生成盔甲。我们使用了两种纹理；也许有一种方法只使用一种。看看你能否改进这个函数。

# 总结

在本章中，我们学习了如何程序生成游戏艺术。我们采取了一个天真的方法开始，简单地使用内置的精灵修改器和随机数生成器，然后算法地生成我们自己的图像。生成程序艺术是一个广阔的主题，你可以写一本关于这个主题的书。希望这一章对你介绍了这个主题。

在下一章中，我们将看一下艺术的表兄弟音频。现在我们的艺术是通过程序生成的，我们将使用类似的技术来创造声音的变化。我们还将使用 SFML 的音频功能来创建专门的 3D 声音，从而为关卡带来更多的深度。


# 第七章：程序修改音频

现在我们的游戏艺术已经接受了程序处理，让我们把注意力转向它的邻居，声音。优秀的声音对于一个好游戏至关重要。想想超级马里奥跳跃的声音有多具有标志性，或者吃豆人中吃豆鬼的声音！出色的配乐和游戏音效帮助玩家沉浸在我们作为游戏开发者创造的世界中。这是一个需要正确完成的领域，这里需要足够的多样性，以便你的玩家不会厌倦一遍又一遍地听到相同的音效。

我们可以手动创建大量的声音效果变体，但这不是程序化的方式！相反，我们将在运行时随机修改声音，以便每次播放时都创建略有不同的声音。然后，我们将利用 SFML 的音频功能创建空间化的 3D 声音，从而为游戏增添更多的深度和沉浸感。

从头开始程序生成音频是一个非常复杂的任务。我们在这个领域的工作将会相对简短，真正局限于对现有声音进行程序化修改，而不是完全创作它们。不过，这将作为一个向音频采用程序化方法的良好介绍。

在本章中，我们将涵盖以下主题：

+   SFML 音频

+   `sf::sound` 和 `sf::music` 之间的区别

+   修改现有的音效

+   创建空间化的 3D 声音

# SFML 音频简介

SFML 有自己专门的音频模块，提供了许多有用的函数，我们可以用来修改声音。SFML 中有两种主要的声音类型：`sf::Sound` 和 `sf::Music`。我们将很快详细介绍这两种类型之间的区别。它还提供了许多函数来编辑声音的属性，如音调和音量。我们将使用这些函数给我们的声音效果增加一些变化。

## sf::Sound 与 sf::Music

在开始处理音频之前，我们需要看一下 `sf::Sound` 和 `sf::Music` 之间的区别：

+   `Sf::Sound` 适用于像拾取物品或脚步声这样的短声音剪辑。声音会完整地加载到内存中，并且准备好播放，没有延迟。

+   `Sf::Music` 用于更长、更大的声音文件，并不会加载到内存中；它在使用时会被流式传输。

这可能看起来是一个细微的差别，但使用正确的类型非常重要。例如，如果我们将游戏的音乐加载到一个 `sf::Sound` 对象中，游戏会使用大量内存！

## sf::SoundBuffer

在 SFML 中创建精灵时，我们创建一个包含比例和位置等信息的 `sf::Sprite` 对象。纹理本身存储在一个 `sf::Texture` 对象中，精灵对象持有对它的引用。`sf::Sound` 类的工作方式与此类似，一个 `sf::SoundBuffer` 对象持有实际的声音，而 `sf::Sound` 只是持有对它的引用。

以下代码显示了如何加载声音：

```cpp
sf::SoundBuffer buffer;
buffer.loadFromFile("sound.wav");

sf::Sound sound;
sound.setBuffer(buffer);
sound.play();
```

`sf::SoundBuffer` 对象必须保持活跃的时间与 `sf::Sound` 对象一样长。如果 `sf::SoundBuffer` 在持有对它引用的 `sf::Sound` 对象之前就超出了作用域，我们将会收到一个错误，因为它会尝试播放一个不再存在的声音。

另外，由于我们只持有对声音缓冲区的引用，它可以在多个声音对象中使用。要播放声音，我们只需调用 `sf::Sound::play`，这将在单独的线程中运行声音。

# 选择一个随机的主音轨

目前，游戏没有声音或音乐。在整本书的过程中，我们一直在频繁地运行游戏，一遍又一遍地听着相同的音轨会变得非常乏味。因此，我们一直等到现在才把它放进去。添加声音是一个非常简单的过程。因此，我们将完整地介绍这个过程。

首先，我们将添加一个主音乐轨，作为游戏的基础。但是，我们不会固定一条音轨，而是添加多种可能性，并在启动时随机选择一种。

让我们首先以通常的方式在枚举器中定义所有可能性。将以下代码添加到`Util.h`中：

```cpp
// Music tracks.
enum class MUSIC_TRACK {
    ALT_1,
    ALT_2,
    ALT_3,
    ALT_4,
    COUNT
};
```

根据`enum`显示，我们将有四个可能的音轨。这些已经包含在`/resources/music/`文件夹中。因此，我们所要做的就是随机选择一条音轨并在游戏开始时加载它。由于我们希望这首音乐立即开始，我们将在`Game`类的构造函数中插入实现这一点的代码。

我们现在已经几次从枚举器中选择了一个随机值，所以应该很熟悉了。我们将生成一个 1 到`MUSIC_TRACK_COUNT`（包括）之间的数字，但是，与其像通常那样将其转换为枚举器类型，我们将把它留在整数形式。这背后的原因很快就会显而易见。

现在，让我们将以下代码添加到`Game::Game`中：

```cpp
// Setup the main game music.
int trackIndex = std::rand() % static_cast<int>(MUSIC_TRACK::COUNT) + 1;
```

现在，我们之所以没有转换为`enum`类型，是因为在加载声音时我们可以很聪明。我们有四个音乐曲目可供选择，它们的名称如下：

+   `msc_main_track_1.wav`

+   `msc_main_track_2.wav`

+   `msc_main_track_3.wav`

+   `msc_main_track_4.wav`

请注意，它们名称中唯一不同的是它们的编号。我们已经生成了 1 到 4 之间的一个数字。因此，我们可以简单地使用这个索引来加载正确的音轨，而不是创建一个`switch`语句，如下所示：

```cpp
// Load the music track.
m_music.openFromFile("../resources/music/msc_main_track_" + std::to_string(trackIndex) + ".wav");
```

现在，当我们调用`m_music.play()`时，声音将被流式传输。最后，通过调用这个函数来完成：

```cpp
m_music.play();
```

如果我们现在运行游戏，我们将听到四个随机选择的音轨中的一个正在播放！

# 添加音效

现在，我们已经有了游戏的主要音乐，让我们把一些音效加入其中！我们已经介绍了`sf::Sound,sf::SoundBuffer`以及如何播放声音，所以我们已经准备好开始了。

我们的游戏中将会有一些音效。一个用于敌人的死亡，一个用于我们被击中，一个用于每个拾取，以及一个用于我们稍后将要播放的火炬的声音。

我们将首先在`Game.h`中为每个声音定义`sf::Sound`变量：

```cpp
/**
 * Torch sound.
 */
sf::Sound m_fireSound;

/**
 * Gem pickup sound.
 */
sf::Sound m_gemPickupSound;

/**
 * Coin pickup sound.
 */
sf::Sound m_coinPickupSound;

/**
* Key collect sound.
*/
sf::Sound m_keyPickupSound;

/**
 * Enemy die sound.
 */
sf::Sound m_enemyDieSound;

/**
 * Player hit sound.
 */
sf::Sound m_playerHitSound;
```

现在，让我们在`Game::Initialize`中初始化这些声音，如下所示：

```cpp
// Load all game sounds.
int soundBufferId;

// Load torch sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_fire.wav");
m_fireSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_fireSound.setLoop(true);
m_fireSound.play();

// Load enemy die sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_enemy_dead.wav");
m_enemyDieSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));

// Load gem pickup sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_gem_pickup.wav");
m_gemPickupSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));

// Load coin pickup sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_coin_pickup.wav");
m_coinPickupSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));

// Load key pickup sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_key_pickup.wav");
m_keyPickupSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));

// Load player hit sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_player_hit.wav");
m_playerHitSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
```

音效初始化后，我们只需在需要时调用`sf::Sound::play`来播放声音。我们在`Game::UpdateItems`函数中处理物品拾取。因此，我们将把这段代码放在那里：

```cpp
// check what type of object it was
switch (m_items[i]->GetType())
{
    case ITEM_GOLD:    
    {
        // Get the amount of gold.
        int goldValue = dynamic_cast<Gold&>(item).GetGoldValue();

        // Add to the gold total.
        m_goldTotal += goldValue;

        // Check if we have an active level goal regarding gold.
        if (m_activeGoal)
        {
            m_goldGoal -= goldValue;
        }

        // Play gold collect sound effect
 m_coinPickupSound.play();
    }
    break;

    case ITEM_GEM:
    {
        // Get the score of the gem.
        int scoreValue = dynamic_cast<Gem&>(item).GetScoreValue();

        // Add to the score total
        m_scoreTotal += scoreValue;

        // Check if we have an active level goal.
        if (m_activeGoal)
        --m_gemGoal;

 // Play the gem pickup sound
 m_gemPickupSound.play();
    }
    break;
}
```

这段代码只涵盖了金币和宝石的拾取。对于所有其他拾取和需要播放声音的情况，比如敌人死亡和玩家受到伤害时，需要做同样的事情。

# 编辑音效

添加了音效后，我们现在可以对它们进行修改以创建多样性。SFML 提供了许多我们可以操作声音的方式，其中包括以下内容：

+   音调

+   音量

+   位置

我们将从最简单的开始：音调。然后，我们将通过创建空间化声音来涵盖音量和位置。每次播放声音效果时，这些值将被随机设置。在我们深入研究之前，让我们创建一个函数来封装声音的修改和播放。这将使我们免于在整个类中重复代码。

# 播放声音函数

与敌人和物品的碰撞在主游戏类中进行处理。因此，我们将在这里放置播放音效的函数。将以下函数声明添加到`Game.h`中：

```cpp
/**
 * Plays the given sound effect, with randomized parameters./
 */
void PlaySound(sf::Sound& sound, sf::Vector2f position = { 0.f, 0.f });
```

这个函数接受两个参数：我们将要播放的声音作为引用传递，以避免昂贵的复制，我们还包括一个参数，用于指定我们想要播放声音的位置。请注意，我们给位置参数一个默认值`{ 0.f, 0.f }`。因此，如果我们希望这样做，它可以被忽略。当我们创建空间化声音时，我们将详细介绍这个参数的作用。

让我们暂时给这个类一个基本的主体，简单地播放通过参数传递的声音：

```cpp
// Plays the given sound effect, with randomized parameters.
void Game::PlaySound(sf::Sound& sound, sf::Vector2f position)
{
    // Play the sound.
    sound.play();
}
```

请注意，如果游戏规模更大，我们有许多声音，将值得将播放声音的行为封装在管理它们的同一类中。这将确保所有与声音的交互都通过一个公共类进行，并保持我们的代码有组织性。

## 音频听众

SFML 带有一个静态听众类。这个类充当了关卡中的耳朵，因此在一个场景中只有一个听众。由于这是一个静态类，我们从不实例化它，并且通过它的静态函数与它交互，比如`sf::Listener::setPosition`。

我所说的“在关卡中的耳朵”，是指在这个位置听到关卡中的所有声音。这就是我们创建 3D 声音的方式。例如，如果声音的来源在听众的右侧，那么在右扬声器中会听到更多声音。看一下下面的图表：

![音频听众](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_07_01.jpg)

在这个图表中，蓝色圆圈代表音频听众的位置，红色圆圈代表声音的位置。你可以看到，由于声音的来源在听众的右侧，我们可以利用这一点来确定声音应该从右扬声器中听到的比从左扬声器中听到的更多。这就是空间化声音的创建方式，我们将在本章后面详细讨论。

对于我们不希望声音被空间化的情况，SFML 给了我们`sf::Sound::setRelativeToListener`函数。这是一个不言自明的函数；声音的位置是相对于听众的位置而不是在场景中的绝对位置。我们将其设置为`true`，并给声音一个位置`{0.f, 0.f, 0.f}`，将其放在听众的正上方。

关于前面的图表，这意味着蓝色的音频听众将直接放在红色的声源的正上方，这意味着它不是空间化的。这是我们希望捡起声音的行为。对于每个声音，我们需要调用这个函数，将`true`作为参数传递。

让我们更新代码来改变这一点：

```cpp
// Load gem pickup sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_gem_pickup.wav");
m_gemPickupSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_gemPickupSound.setRelativeToListener(true);
// Load coin pickup sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_coin_pickup.wav");
m_coinPickupSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_coinPickupSound.setRelativeToListener(true);

// Load key pickup sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_key_pickup.wav");
m_keyPickupSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_keyPickupSound.setRelativeToListener(true);

// Load player hit sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_player_hit.wav");
m_playerHitSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_playerHitSound.setRelativeToListener(true); 

```

与玩家位置相同的位置产生的声音需要这个。例如，物品只有在敌人占据相同空间时才会被捡起。你永远不会从远处捡起物品，所以声音永远不会被空间化。

## 创建音调波动

音调是听到声音的感知频率。SFML 提供了一种增加或减少声音音调的方法，它通过增加/减少播放速度来实现。播放得更快，声音就会听起来更高。默认值为 1，因此生成一个小于或大于 1 的数字将给我们带来音调的波动。

我们将把这个行为添加到我们的新的`Game::PlaySound`函数中。首先，我们将生成一个介于 0.95 和 1.05 之间的数字，设置音调，并播放声音，如下所示：

```cpp
// Plays the given sound effect, with randomized parameters.
void Game::PlaySound(sf::Sound& sound, sf::Vector2f position)
{
 // Generate and set a random pitch.
 float pitch = (rand() % 11 + 95) / 100.f;
 sound.setPitch(pitch);

    // Play the sound.
    sound.play();
}
```

现在，每当我们想要一个声音有这种音调波动时，我们需要通过这个函数播放它，而不是直接播放。这适用于所有的捡起声音。所以，让我们实现这个改变：

```cpp
// check what type of object it was
switch (m_items[i]->GetType())
{
    case ITEM_GOLD:
    {
        // Get the amount of gold.
        int goldValue = dynamic_cast<Gold&>(item).GetGoldValue();

        // Add to the gold total.
        m_goldTotal += goldValue;

        // Check if we have an active level goal regarding gold.
        if (m_activeGoal)
        {
            m_goldGoal -= goldValue;
        }

 // Play gold collect sound effect
 PlaySound(m_coinPickupSound);
    }
    break;

    case ITEM_GEM:
    {
        // Get the score of the gem.
        int scoreValue = dynamic_cast<Gem&>(item).GetScoreValue();

        // Add to the score total
        m_scoreTotal += scoreValue;

        // Check if we have an active level goal.
        if (m_activeGoal)
        {
            --m_gemGoal;
        }

 // Play the gem pickup sound
 PlaySound(m_gemPickupSound);
    }
    break;
}
```

如果我们现在玩游戏并捡起一些物品，我们会听到每次捡起声音都略有不同，给声音效果带来了一些变化。如果你希望在捡起钥匙、敌人死亡和玩家受到攻击时播放的声音也有音调波动，确保它们也通过这个函数播放，而不是直接播放。

# 3D 声音-空间化

现在让我们看看如何创建一些 3D 音频来为游戏场景增加深度。当我们走过一个火炬时，我们希望听到它从我们身边经过，我们希望能够听到敌人从一个方向向我们走来。空间化允许我们做到这一点，SFML 有很好的功能来帮助我们实现这一点。

## 音频听众

我们已经定义了音频听者是什么以及它是如何用来创建空间化音频的。作为实现这一目标的第一步，我们需要在每次更新后设置听者的位置，确保关卡中的所有声音都是从玩家的视角听到的。

在每个游戏更新的开始，我们重新计算玩家的位置。在这之后，我们可以将听者类的位置更新到这个新位置。记住`sf::Listener`是一个静态类，我们不需要实例化它。我们所需要做的就是静态调用`sf::Listener::setPosition`。

让我们将这个附加到`Game::Update`函数中，如下所示：

```cpp
// Update the player.
m_player.Update(timeDelta, m_level);

// Store the player position as it's used many times.
sf::Vector2f playerPosition = m_player.GetPosition();

// Move the audio listener to the players location.
sf::Listener::setPosition(playerPosition.x, playerPosition.y, 0.f);

// If the player is attacking create a projectile.
if (m_player.IsAttacking())
{
```

继续前进，我们现在可以确保听者处于正确的位置，以便我们创建 3D 声音。

## 最小距离

最小距离是玩家在听到声音的全音量之前可以接近声源的最近距离。想象它是围绕声源的一个圆圈。这个圆圈的半径是`MinDistance`，如下图所示：

![最小距离](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_07_02.jpg)

在我们的情况下，声音的最小距离在游戏过程中不会改变，这意味着我们可以在加载声音时在`Game::Initialize`函数中设置它们的值一次。我们在这里使用的值是个人偏好的问题，但我发现最小距离为`80.f`效果很好。让我们设置这些值。

对`Game::Initialize`函数进行以下修改：

```cpp
// Load torch sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_fire.wav");
m_fireSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_fireSound.setLoop(true);
m_fireSound.setMinDistance(80.f);
m_fireSound.play();

// Load enemy die sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_enemy_dead.wav");
m_enemyDieSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_enemyDieSound.setMinDistance(80.f); 

```

## 衰减

衰减基本上意味着“减少”或“使某物变小”。在音频的上下文中，它是声音随着我们远离声源而变得更安静的速率。当我们超出最小距离时，这就会生效，并用于计算声音的音量。

在下图中，渐变代表声音的音量。左边的图显示了高衰减，声音下降得非常快，而右边的图显示了低衰减，声音下降得更平稳：

![衰减](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_07_03.jpg)

现在，让我们给我们的两个声音一个衰减值，就像我们在最小距离上做的那样。同样，这里使用的值取决于您，但我发现一个`5.f`的衰减值，略高于默认值，可以创建一个不错的淡出效果。

对`Game::Initialize`函数进行以下修改：

```cpp
// Load torch sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_fire.wav");
m_fireSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_fireSound.setLoop(true);
m_fireSound.setAttenuation(5.f);
m_fireSound.setMinDistance(80.f);
m_fireSound.play();

// Load enemy die sound.
soundBufferId = SoundBufferManager::AddSoundBuffer("../resources/sounds/snd_enemy_dead.wav");
m_enemyDieSound.setBuffer(SoundBufferManager::GetSoundBuffer(soundBufferId));
m_enemyDieSound.setAttenuation(5.f);
m_enemyDieSound.setMinDistance(80.f);
```

如果我们现在运行游戏，我们会看到当我们靠近火炬时，它们会变得更响亮，当我们走开时，它们会变得更安静。然而，它们并不是 3D 的。为此，我们需要更新声音的源！

## 声音的位置

声音的位置就是它在场景中的位置。正是这个位置和听者的位置被用来创建 3D 效果，并确定声音应该从哪个扬声器播放出来。

### 提示

要使用空间定位，您的声音需要是**单声道**（只有一个声道）。这个项目提供的声音是这样的，但是如果您要添加自己的声音，您需要记住这一点！具有多个声道的声音已经明确决定如何使用扬声器。

现在我们已经设置了衰减和最小距离，我们现在可以设置声音的正确位置，这样我们就可以听到 3D 效果。游戏中有两种声音将会是 3D 的：火炬的声音和敌人被杀死时的声音。由于关卡中有多个火炬，我们在这里有一些工作要做。我们将从两者中较简单的一个开始：敌人被杀死时的声音。

### 固定位置

首先，我们需要更新`Game::PlaySound`函数。目前它只生成一个随机音调，但我们需要它设置位置。您可能还记得，我们通过给位置参数一个默认值`{0.f, 0.f }`来使其成为可选参数。当我们传递一个位置并覆盖默认值时，这意味着我们想要利用 3D 声音。当我们留空时，这意味着我们不想这样做，声音将相对于听者。因此，`{0.f, 0.f, 0.f}`正是我们需要的。

让我们连接`Game::PlaySound`中的位置参数，并使用它来设置声音的位置，如下所示：

```cpp
// Plays the given sound effect, with randomized parameters.
void Game::PlaySound(sf::Sound& sound, sf::Vector2f position)
{
    // Generate and set a random pitch.
    float pitch = (rand() % 11 + 95) / 100.f;
    sound.setPitch(pitch);

 // Set the position of the sound.
 sound.setPosition(position.x, position.y, 0.f);

    // Play the sound.
    sound.play();
}
```

声音的位置在三维空间中运作，但由于我们正在处理二维声音，我们可以将*Z*值保留为`0.f`。现在，当我们确定敌人已被杀死时，我们只需调用此函数并传递正确的声音和敌人的位置，因为声音就是来自那里，如下所示：

```cpp
// 1 in 5 change of spawning potion.
else if ((std::rand() % 5) == 1)
{
    position.x += std::rand() % 31 - 15;
    position.y += std::rand() % 31 - 15;
    SpawnItem(ITEM::POTION, position);
}

// Play enemy kill sound.
PlaySound(m_enemyDieSound, enemy.GetPosition());

// Delete enemy.
enemyIterator = m_enemies.erase(enemyIterator);
```

现在是再次运行游戏并听听我们的成果的时候了。当我们杀死敌人时，我们可以听到他们离得越远，声音就越微弱。此外，如果我们向右边杀死一个敌人，我们会听到声音来自那个方向！为了完成我们的声音工作，让我们将相同的技术应用到火炬上，真正为关卡的音频增加一些深度。

### 注意

3D 声音的清晰度将取决于您的设置。例如，耳机可以让您轻松地听到不同方向的声音，而笔记本电脑扬声器可能就不那么清晰了。

### 移动位置

我们将为最后一个区域添加 3D 声音的是关卡中的火炬。当我们在关卡中走动时，能够在远处微弱地听到火炬的声音，或者当我们走过时在耳机中近距离地听到。然而，存在一个小问题。我们知道声音的空间化是在声音和听者相距一定距离时实现的。但是如果我们有一个需要来自多个位置的声音怎么办？我们可以为每个火炬设置一个声音，但这样很浪费。相反，我们将计算哪个火炬离玩家最近，并将其用作声源。

作为我们主要的更新函数的一部分，我们需要查看所有的火炬，并确定哪一个离玩家最近。当玩家在关卡中走动时，声源会切换，给我们一种每个火炬都发出自己的声音的印象，而实际上我们只有一个声源。

我们已经有一个函数来找到两个对象之间的距离，即`Game::DistanceBetweenPoints`。有了这个，我们可以遍历所有的火炬，并使用这个函数来获取到玩家的距离。让我们更新`Game::Update`函数以包括这个计算，如下所示：

```cpp
// Update all projectiles.
UpdateProjectiles(timeDelta);

// Find which torch is nearest the player.
auto torches = m_level.GetTorches();

// If there are torches.
if (!torches->empty())
{
 // Store the first torch as the current closest.
 std::shared_ptr<Torch> nearestTorch = torches->front();
 float lowestDistanceToPlayer = DistanceBetweenPoints(playerPosition, nearestTorch->GetPosition());

 for (std::shared_ptr<Torch> torch : *torches)
 {
 // Get the distance to the player.
 float distanceToPlayer = DistanceBetweenPoints(playerPosition, torch->GetPosition());
 if (distanceToPlayer < lowestDistanceToPlayer)
 {
 lowestDistanceToPlayer = distanceToPlayer;
 nearestTorch = torch;
 }
 }
}

// Check if the player has moved grid square.
Tile* playerCurrentTile = m_level.GetTile(playerPosition);
```

正如您所看到的，对于关卡中的每个火炬，我们都会计算它离玩家有多远。如果它比我们上次检查的火炬更近，我们就将其标记为最近的。当这段代码完成时，我们最终得到了存储在名为`nearestTorch`的共享指针中的最近的火炬。

确定了最近的火炬后，我们可以使用它的位置作为火焰声音的位置。现在，对于其余的声音，我们一直在使用新的`Game::PlaySound`函数，但这里不适用。我们的火焰声音已经在循环播放，我们不需要重新开始它。我们只需要设置它的位置，所以我们会直接这样做。

让我们再次更新那段代码：

```cpp
    // Get the distance to the player.
    float distanceToPlayer = DistanceBetweenPoints(playerPosition, torch->GetPosition());
    if (distanceToPlayer < lowestDistanceToPlayer)
        {
            lowestDistanceToPlayer = distanceToPlayer;
            nearestTorch = torch;
        }
    }

 m_fireSound.setPosition(nearestTorch->GetPosition().x, nearestTorch->GetPosition().y, 0.0f);
}

// Check if the player has moved grid square.
Tile* playerCurrentTile = m_level.GetTile(playerPosition);
```

让我们最后一次运行项目！现在我们应该听到一个随机的音乐曲目，一些我们的音效将以不断变化的音调播放，火炬和敌人死亡的声音将被空间化。

# 练习

为了帮助您测试对本章内容的理解，这里有一些练习供您练习。它们对本书的其余部分并不是必不可少的，但是练习它们将有助于您评估所涵盖材料的优势和劣势：

1.  将更多的曲目添加到主曲目列表中。

1.  在“关卡”中添加一个空间化的声音，当门打开时能听到。当玩家收集到“关卡”的钥匙时，能听到背景中门滑动打开的声音将帮助他们找到它。

1.  在“关卡”中添加一些大气的音效；这些音效应该是空间化的，并且必须在随机的时间间隔内播放。到目前为止我们还没有涉及到这样的内容，所以这可能是一个挑战。

# 总结

在本章中，我们使用了 SFML 内置的音频修改器来对我们的音效进行修改。我们还利用这些修改器来创建空间化的 3D 声音，为我们的游戏场景增添了更多的深度。

在下一章中，我们将运用到目前为止学到的一切来创建复杂的程序行为和机制，包括寻路和独特的关卡目标。我们将赋予我们的敌人智能，让他们穿越关卡并追逐玩家，我们还将为玩家创建一个独特的关卡目标，并为其提供独特的奖励。
