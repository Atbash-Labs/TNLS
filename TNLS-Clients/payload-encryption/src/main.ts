import './style.css'
import { setupConnect } from './connect'
import { setupSubmit } from './submit'
import { setupEncrypt } from './encrypt'
import { setupSignMessage } from './sign'

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div>
    <h1>TNLS Demo</h1>
    <div id="form">
      <form name="inputForm">
      <label for="input1">$USD value of offchain assets:  </label>
      <input type="number" placeholder="$" id="input1" name="input1" />
      <br>
      <label for="input2">$USD value of onchain assets:  </label>
      <input type="text" placeholder="$" id="input2" name="input2" />
      <br>
      <label for="input3">$USD value of liabilities (loans, mortgages):  </label>
      <input type="text" placeholder="$" id="input3" name="input3" />
      <br>
      <label for="input4">$USD value of loan payments missed in last 5 years:  </label>
      <input type="text" placeholder="$" id="input4" name="input4" />
      <br>
      <label for="input5">$USD value of salary/income stream:  </label>
      <input type="text" placeholder="$" id="input5" name="input5" />
        <br>
      <button id="submit">Submit</button>
      <button id="encrypt" type="button"></button>
      <div id="preview" style="word-wrap: break-word;">
      </div>
    </div>
    <div class="card">
      <button id="connect" type="button"></button>
      <button id="sign" type="button"></button>
      <div id="account"></div>
    </div>
  </div>
`
setupSubmit(document.querySelector<HTMLButtonElement>('#submit')!)
setupEncrypt(document.querySelector<HTMLButtonElement>('#encrypt')!)
setupConnect(document.querySelector<HTMLButtonElement>('#connect')!)
setupSignMessage(document.querySelector<HTMLButtonElement>('#sign')!)