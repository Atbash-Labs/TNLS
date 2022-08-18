import { createRouter, createWebHistory } from "vue-router";
import HomeView from "../views/HomeView.vue";
import DemoView from "../views/DemoView.vue";
import MetaView from "../views/MetaView.vue";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: "/",
      name: "home",
      component: HomeView,
    },
    {
      path: "/demo",
      name: "demo",
      component: DemoView,
    },
    {
      path: "/metamask",
      name: "metamask",
      component: MetaView,
    },
    {
      path: "/about",
      name: "about",
      // route level code-splitting
      // this generates a separate chunk (About.[hash].js) for this route
      // which is lazy-loaded when the route is visited.
      component: () => import("../views/AboutView.vue"),
    },
  ],
});

export default router;
