<template>
  <div class="about">
    <h1>Millionaires' Problem</h1>
    <p>
      Yao's Millionaires' problem is a secure multi-party computation problem
      introduced in 1982 by computer scientist and computational theorist Andrew
      Yao. The problem discusses two millionaires, Alice and Bob, who are
      interested in knowing which of them is richer without revealing their
      actual wealth.
    </p>
    <p>
      This problem is analogous to a more general problem where there are two
      numbers a and b and the goal is to determine whether the inequality a ≥ b
      is true or false without revealing the actual values of a and b.
    </p>
    <p>
      The Millionaires' problem is an important problem in cryptography, the
      solution of which is used in e-commerce and data mining. Commercial
      applications sometimes have to compare numbers that are confidential and
      whose security is important.
    </p>
    <p>
      Many solutions have been introduced for the problem. The first solution,
      presented by Yao, is exponential in time and space.
    </p>
    <a
      href="https://en.wikipedia.org/wiki/Yao%27s_Millionaires%27_problem"
      target="_blank"
      >source</a
    >
  </div>
</template>

<style>
@media (min-width: 1024px) {
  .about {
    align-items: center;
  }
  h1 {
    font-size: 1.6rem;
    font-weight: 500;
    margin-bottom: 1rem;
    color: var(--color-heading);
  }
  p {
    margin-bottom: 1rem;
    color: var(--color-text);
  }
}
</style>
