import './style.css'
import { setupConnect } from './connect'
import { setupSignMessage } from './sign'
import { ethers } from 'ethers'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div>
    <h1>TNLS Demo</h1>
    <div id="form">
      <form id="data">
      <label>$USD value of offchain assets:  </label>
      <input type="text" placeholder="$" />
      <br>
      <label>$USD value of onchain assets:  </label>
      <input type="text" placeholder="$" />
      <br>
      <label>$USD value of liabilities (loans, mortgages):  </label>
      <input type="text" placeholder="$" />
      <br>
      <label>$USD value of loan payments missed in last 5 years:  </label>
      <input type="text" placeholder="$" />
      <br>
      <label>$USD value of salary/income stream:  </label>
      <input type="text" placeholder="$" />
        <br>
      <button id="submit">Submit</button>
    </div>
    <div class="card">
      <button id="connect" type="button"></button>
      <button id="sign" type="button"></button>
      <div id="account"></div>
    </div>

  </div>
`

setupConnect(document.querySelector<HTMLButtonElement>('#connect')!)
setupSignMessage(document.querySelector<HTMLButtonElement>('#sign')!)

