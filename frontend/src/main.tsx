import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'

// Office.initialize must wrap your React bootstrapper 
// so the add-in waits for Outlook to fully establish communication.
Office.onReady((info) => {
  if (info.host === Office.HostType.Outlook) {
    ReactDOM.createRoot(document.getElementById('root')!).render(
      <React.StrictMode>
        <App />
      </React.StrictMode>,
    )
  }
});