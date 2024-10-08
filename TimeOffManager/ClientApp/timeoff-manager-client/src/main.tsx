import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import {
  createBrowserRouter,
  RouterProvider,
} from "react-router-dom";
import WorkSpaceMain from './components/workspace/workspace-main';
import LandingMain from './components/landning/landing-main';
import TeamsManagerMain from './components/teams-manager/teams-manager-main';
import AcceptInvitePage from './components/shared/accept-invite';

const router = createBrowserRouter([
  {
    path: "/workspace",
    element: <WorkSpaceMain/>,
  },
  {
    path: "/",
    element: <LandingMain/>,
  },
  {
    path: "/teams-manager",
    element: <TeamsManagerMain/>
  },
  {
    path: "/accept-invite",
    element: <AcceptInvitePage/>
  }
]);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
    <App />
  </React.StrictMode>,
)
