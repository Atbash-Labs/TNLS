import { ethers } from 'ethers'

export async function setupSubmit(element: HTMLButtonElement) {
    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);
    const [myAddress] = await provider.send("eth_requestAccounts", []);

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()

        const offchain_assets = document.querySelector<HTMLFormElement>('#input1')?.value;
        const onchain_assets = document.querySelector<HTMLFormElement>('#input2')?.value;
        const liabilities = document.querySelector<HTMLFormElement>('#input3')?.value;
        const missed_payments = document.querySelector<HTMLFormElement>('#input4')?.value;
        const income = document.querySelector<HTMLFormElement>('#input5')?.value;

        const data = JSON.stringify({
        address: myAddress,
        offchain_assets: Number(offchain_assets),
        onchain_assets: Number(onchain_assets),
        liabilities: Number(liabilities),
        missed_payments: Number(missed_payments),
        income: Number(income)
        })

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <p >
        ${data}
        </p>
        `

        // document.querySelector<HTMLDivElement>('#test')!.innerHTML = `
        //   <p>
        //   "data": {<br>
        //     &emsp;"address":"${myAddress}",<br>
        //     &emsp;"offchain_assets":${input1},<br>
        //     &emsp;"onchain_assets":${input2},<br>
        //     &emsp;"liabilities":${input3},<br>
        //     &emsp;"missed_payments":${input4},<br>
        //     &emsp;"income":${input5}<br>
        //   }
        //   </p>
        // `
    })
}