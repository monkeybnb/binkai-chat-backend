import { Inject, Injectable, OnApplicationBootstrap } from '@nestjs/common';
import OpenAI from 'openai';
import {
  Agent,
  Wallet,
  Network,
  NetworkType,
  NetworksConfig,
  UUID,
  ExtensionWallet,
} from '@binkai/core';
import { PostgresDatabaseAdapter } from '@binkai/postgres-adapter';
import { EventEmitter } from 'events';
import { BinkProvider } from '@binkai/bink-provider';
import { BnbProvider, SolanaProvider } from '@binkai/rpc-provider';
import { ExampleToolExecutionCallback } from '@/shared/tools/tool-execution';
import { WalletPlugin } from '@binkai/wallet-plugin';
import { BirdeyeProvider } from '@binkai/birdeye-provider';
import { Server, Socket } from 'socket.io';
import { Observable } from 'rxjs';
import { PancakeSwapProvider } from '@binkai/pancakeswap-provider';
import { JsonRpcProvider } from 'ethers';
import { Connection } from '@solana/web3.js';
import { KnowledgePlugin } from '@binkai/knowledge-plugin';
import { FourMemeProvider } from '@binkai/four-meme-provider';
import { OkxProvider } from '@binkai/okx-provider';
import { deBridgeProvider } from '@binkai/debridge-provider';
import { BridgePlugin } from '@binkai/bridge-plugin';
import { StakingPlugin } from '@binkai/staking-plugin';
import { VenusProvider } from '@binkai/venus-provider';
import { ThenaProvider } from '@binkai/thena-provider';
import { JupiterProvider } from '@binkai/jupiter-provider';
import { SwapPlugin } from '@binkai/swap-plugin';
import { AlchemyProvider } from '@binkai/alchemy-provider';
import { TokenPlugin } from '@binkai/token-plugin';
import { ImagePlugin } from '@binkai/image-plugin';
import { KyberProvider } from '@binkai/kyber-provider';
import { ListaProvider } from '@binkai/lista-provider';
import { KernelDaoProvider } from '@binkai/kernel-dao-provider';
import { OkuProvider } from '@binkai/oku-provider';

// Constants for system prompt - to avoid duplication
const SYSTEM_PROMPT = `You are a BINK AI assistant. You can help user to query blockchain data. You are able to perform swaps and get token information on multiple chains. If you do not have the token address, you can use the symbol to get the token information before performing a swap.

Your response format:
BINK's tone is informative, bold, and subtly mocking, blending wit with a cool edge for the crypto crowd. Think chain-vaping degen energy, but refined—less "honey, sit down" and more "I've got this, you don't."
Fiercely Casual – Slang, laid-back flow, and effortless LFG vibes.
Witty with a Jab – Dry humor, sharp one-liners—more smirk, less roast.
Confident & Cool – Market takes with swagger—just facts, no fluff.
Crew Leader – Speaks degen, leads with "pay attention" energy.
Subtle Shade – Calls out flops with a "nice try" tone, not full-on slander.
BINK isn't here to babysit. It's sharp, fast, and always ahead of the curve—dropping crypto insights with a mocking wink, perfect for X's chaos.

CRITICAL: 
1. Format your responses in Markdown style.
2. DO NOT use HTML tags.
3. Use Markdown formatting like **bold**, *italic*, \`code\`, \`\`\`preformatted\`\`\`, and [links](URL).
4. When displaying token information or swap details:
   - Use **bold** for important values and token names
   - Use \`code\` for addresses and technical details
   - Use *italic* for additional information
5. If has limit order, show list id limit order.`;

const BNB_RPC = 'https://bsc-dataseed1.binance.org';
const ETH_RPC = 'https://eth.llamarpc.com';
const SOL_RPC = 'https://api.mainnet-beta.solana.com';
const chains = ['bnb', 'ethereum', 'solana'];

@Injectable()
export class AiService implements OnApplicationBootstrap {
  private openai: OpenAI;
  private networks: NetworksConfig['networks'];
  private network: Network;
  private wallet: ExtensionWallet;
  private birdeyeApi: BirdeyeProvider;
  private postgresAdapter: PostgresDatabaseAdapter;
  private binkProvider: BinkProvider;
  private bnbProvider: BnbProvider;
  private mapAgent: Record<string, Agent> = {};
  private mapWallet: Record<string, ExtensionWallet> = {};
  private io: Server;
  private evmProvider: any;
  private eventEmitter: EventEmitter;
  private alchemyApi: AlchemyProvider;
  @Inject('BSC_CONNECTION')
  private bscProvider: JsonRpcProvider;
  private solanaProvider: SolanaProvider;

  constructor(@Inject('OPENAI') openai: OpenAI) {
    this.openai = openai;
    this.networks = {
      bnb: {
        type: 'evm' as NetworkType,
        config: {
          chainId: 56,
          rpcUrl: process.env.BSC_RPC_URL || BNB_RPC,
          name: 'BNB Chain',
          nativeCurrency: {
            name: 'BNB',
            symbol: 'BNB',
            decimals: 18,
          },
        },
      },
      ethereum: {
        type: 'evm' as NetworkType,
        config: {
          chainId: 1,
          rpcUrl: process.env.ETHEREUM_RPC_URL || ETH_RPC,
          name: 'Ethereum',
          nativeCurrency: {
            name: 'Ether',
            symbol: 'ETH',
            decimals: 18,
          },
        },
      },
      solana: {
        type: 'solana' as NetworkType,
        config: {
          rpcUrl: process.env.SOLANA_RPC_URL || SOL_RPC,
          name: 'Solana',
          nativeCurrency: {
            name: 'Solana',
            symbol: 'SOL',
            decimals: 9,
          },
        },
      },
    };

    this.postgresAdapter = new PostgresDatabaseAdapter({
      connectionString: process.env.POSTGRES_AI_URL,
    });
    this.network = new Network({ networks: this.networks });

    this.bnbProvider = new BnbProvider({
      rpcUrl: BNB_RPC,
    });

    this.birdeyeApi = new BirdeyeProvider({
      apiKey: process.env.BIRDEYE_API_KEY,
    });

    this.binkProvider = new BinkProvider({
      apiKey: process.env.BINK_API_KEY,
      baseUrl: process.env.BINK_API_URL,
      imageApiUrl: process.env.IMAGE_API_URL,
    });

    this.bnbProvider = new BnbProvider({
      rpcUrl: process.env.BSC_RPC_URL,
    });

    this.alchemyApi = new AlchemyProvider({
      apiKey: process.env.ALCHEMY_API_KEY,
    });

    this.eventEmitter = new EventEmitter();

    this.solanaProvider = new SolanaProvider({
      rpcUrl: process.env.RPC_URL,
    });

    console.log('🔍 [AiService] [constructor] Initializing AiService...');
  }

  async subscribeWallet(threadId: string, socket: Socket) {
    try {
      const wallet = new ExtensionWallet(this.network);
      wallet.connect(socket);
      this.mapWallet[threadId] = wallet;
    } catch (error) {
      console.error('🚨 [AiService] [subscribeWallet] Error:', error);
      throw new Error(error.message);
    }
  }
  async unsubscribeWallet(threadId: string) {
    try {
      const wallet = this.mapWallet[threadId];
      if (wallet) {
        wallet.disconnect();
        delete this.mapWallet[threadId];
        delete this.mapAgent[threadId];
      }
    } catch (error) {
      console.error('🚨 [AiService] [unsubscribeWallet] Error:', error);
      throw new Error(error.message);
    }
  }

  /**
   * Get existing Agent or create a new one for the thread
   * @param threadId - Thread ID to get or create agent for
   * @returns Promise resolving to the Agent instance and wallet
   * @throws Error if no wallet is found for the thread
   */
  private async getOrCreateAgent(
    threadId: string,
  ): Promise<{ agent: Agent; wallet: ExtensionWallet }> {
    // Get the wallet from the map
    console.log(
      '🔍 [AiService] [getOrCreateAgent] Number of active wallets:',
      Object.keys(this.mapWallet).length,
    );
    const wallet = this.mapWallet[threadId];
    if (!wallet) {
      console.log(
        `🔴 [AiService] [getOrCreateAgent] No wallet found for threadId:`,
        threadId,
      );
      throw new Error('Connect socket to wallet');
    }

    // Get existing agent or create a new one
    let agent = this.mapAgent[threadId];

    if (!agent) {
      console.log(
        `🔄 [AiService] [getOrCreateAgent] Initializing wallet plugin and agent...`,
      );

      // Create and initialize wallet plugin
      const bscChainId = 56;
      const pancakeswap = new PancakeSwapProvider(this.bscProvider, bscChainId);
      // const okx = new OkxProvider(this.bscProvider, bscChainId);
      const fourMeme = new FourMemeProvider(this.bscProvider, bscChainId);
      const venus = new VenusProvider(this.bscProvider, bscChainId);
      const kernelDao = new KernelDaoProvider(this.bscProvider, bscChainId);
      const oku = new OkuProvider(this.bscProvider, bscChainId);
      const kyber = new KyberProvider(this.bscProvider, bscChainId);
      const jupiter = new JupiterProvider(new Connection(process.env.RPC_URL));
      const imagePlugin = new ImagePlugin();
      const swapPlugin = new SwapPlugin();
      const tokenPlugin = new TokenPlugin();
      const knowledgePlugin = new KnowledgePlugin();
      const bridgePlugin = new BridgePlugin();
      const debridge = new deBridgeProvider(
        [this.bscProvider, new Connection(process.env.RPC_URL)],
        56,
        7565164,
      );
      const walletPlugin = new WalletPlugin();
      const stakingPlugin = new StakingPlugin();
      const thena = new ThenaProvider(this.bscProvider, bscChainId);
      const lista = new ListaProvider(this.bscProvider, bscChainId);

      await Promise.all([
        swapPlugin.initialize({
          defaultSlippage: 0.5,
          defaultChain: 'bnb',
          providers: [pancakeswap, fourMeme, thena, jupiter, oku, kyber],
          supportedChains: ['bnb', 'ethereum', 'solana'], // These will be intersected with agent's networks
        }),
        tokenPlugin.initialize({
          defaultChain: 'bnb',
          providers: [this.birdeyeApi, fourMeme as any],
          supportedChains: ['solana', 'bnb', 'ethereum'],
        }),
        await knowledgePlugin.initialize({
          providers: [this.binkProvider],
        }),
        await imagePlugin.initialize({
          defaultChain: 'bnb',
          providers: [this.binkProvider],
        }),
        await bridgePlugin.initialize({
          defaultChain: 'bnb',
          providers: [debridge],
          supportedChains: ['bnb', 'solana'],
        }),
        await walletPlugin.initialize({
          defaultChain: 'bnb',
          providers: [
            this.bnbProvider,
            this.birdeyeApi,
            this.alchemyApi,
            this.solanaProvider,
          ],
          supportedChains: ['bnb', 'solana', 'ethereum'],
        }),
        await stakingPlugin.initialize({
          defaultSlippage: 0.5,
          defaultChain: 'bnb',
          providers: [venus, kernelDao, lista],
          supportedChains: ['bnb', 'ethereum'], // These will be intersected with agent's networks
        }),
      ]);

      // Create new agent
      agent = new Agent(
        {
          model: 'gpt-4.1',
          temperature: 0,
          systemPrompt: SYSTEM_PROMPT,
        },
        wallet,
        this.networks,
      );

      // Initialize agent
      await agent.initialize();
      await agent.registerPlugin(swapPlugin as any);
      await agent.registerPlugin(tokenPlugin as any);
      await agent.registerDatabase(this.postgresAdapter);
      await agent.registerPlugin(knowledgePlugin as any);
      await agent.registerPlugin(bridgePlugin);
      await agent.registerPlugin(walletPlugin);
      await agent.registerPlugin(stakingPlugin as any);
      await agent.registerPlugin(imagePlugin as any);

      // const toolExecutionCallback = new ExampleToolExecutionCallback(
      //   threadId,
      //   this.bot,
      //   messageId,
      //   onMessage,
      // );
      console.log(
        '🔔 [AiService] [getOrCreateAgent] Registering tool execution callback...',
      );
      agent.registerToolExecutionCallback(new ExampleToolExecutionCallback());

      // Store agent in map for future use
      this.mapAgent[threadId] = agent;
    }

    return { agent, wallet };
  }

  /**
   * Handle agent interaction and get a response
   */
  async handleAgent(
    threadId: string,
    input: string,
    onMessage?: (message: string) => void,
  ) {
    try {
      console.log(
        '🔍 [AiService] [handleAgent] Processing input for threadId:',
        threadId,
      );

      // Get or create agent
      const { agent } = await this.getOrCreateAgent(threadId);

      // Execute agent
      const inputResult = await agent.execute({
        input: input.trim(),
        threadId: threadId as UUID,
      });

      // Process result
      const result = inputResult;

      if (onMessage) {
        onMessage(result);
      }

      return result;
    } catch (error) {
      console.error('🚨 [AiService] [handleAgent] Error:', error);
      throw new Error(error.message);
    }
  }

  /**
   * Stream response from Agent with real-time updates
   * @param threadId - The thread ID for context
   * @param input - User input message
   * @returns Observable that emits each chunk of the response
   */
  handleAgentStream(threadId: string, input: string): Observable<string> {
    return new Observable<string>((observer) => {
      try {
        console.log(
          `✅ [AiService] [handleAgentStream] Processing input for threadId:`,
          threadId,
        );

        // Use async IIFE to handle async operations within Observable
        (async () => {
          try {
            // Get or create agent
            const { agent } = await this.getOrCreateAgent(threadId);

            // Execute agent with streaming
            await this.executeAgentWithStreaming(
              agent,
              input,
              threadId,
              observer,
            );
          } catch (error) {
            console.error(`🔴 [AiService] [handleAgentStream] Error:`, error);
            observer.error(error);
          }
        })();
      } catch (error) {
        console.error(
          `🔴 [AiService] [handleAgentStream] General error:`,
          error,
        );
        observer.error(error);
      }

      // Cleanup function if observer is unsubscribed
      return () => {
        console.log(
          `✅ [AiService] [handleAgentStream] Client disconnected, cleaning up`,
        );
      };
    });
  }

  /**
   * Helper method to execute agent with streaming output
   * @private
   */
  private async executeAgentWithStreaming(
    agent: Agent,
    input: string,
    threadId: string,
    observer: any,
  ): Promise<void> {
    try {
      // Since executeStream may not exist on Agent type yet, use fallback approach
      // Fallback to non-streaming execution
      const result = await agent.execute({
        input: input.trim(),
        threadId: threadId as UUID,
      });

      // Simulate streaming by breaking response into smaller chunks
      const chunks = this.simulateChunkedResponse(result);
      console.log('🔍 [AiService] [executeAgentWithStreaming] Chunks:', chunks);
      for (const chunk of chunks) {
        observer.next(` ${chunk}`);
        // Add small delay between chunks to simulate typing
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      observer.complete();
    } catch (error) {
      console.error(`🔴 [AiService] [executeAgentWithStreaming] Error:`, error);
      observer.error(error);
    }
  }

  /**
   * Simulate chunked response by breaking text into smaller pieces
   * @private
   */
  private simulateChunkedResponse(text: string): string[] {
    // Split by words to create natural-looking chunks
    const words = text.split(' ');
    const chunks: string[] = [];
    let currentChunk = '';

    // Create chunks of 1-5 words (randomly)
    for (const word of words) {
      currentChunk += (currentChunk ? ' ' : '') + word;

      // Randomly decide if we should end current chunk
      if (currentChunk.length > 10 && Math.random() > 0.7) {
        chunks.push(currentChunk);
        currentChunk = '';
      }
    }

    // Add any remaining text
    if (currentChunk) {
      chunks.push(currentChunk);
    }

    return chunks;
  }

  async onApplicationBootstrap() {
    console.log('🚀 [AiService] Application bootstrapped');
  }
}

async function mockExtensionWalletClient(network: Network) {
  //Fake wallet for testing
  // const wallet = new Wallet(
  //   {
  //     seedPhrase:
  //       settings.get('WALLET_MNEMONIC') ||
  //       'test test test test test test test test test test test junk',
  //     index: 0,
  //   },
  //   network,
  // );
  // const socket = ioClient('http://localhost:3000');
  // socket.on('connect', () => {
  //   console.log('connected to extension wallet client');
  // });
  // socket.on('disconnect', () => {
  //   console.log('disconnected from extension wallet client');
  // });
  // socket.on('error', error => {
  //   console.log('error from extension wallet client', error);
  // });
  // socket.on('get_address', async (data, callback) => {
  //   console.log('get_address from extension wallet client', data);
  //   callback({ address: await wallet.getAddress(data.network) });
  // });
  // socket.on('sign_message', async (data, callback) => {
  //   console.log('sign_message from extension wallet client', data);
  //   callback({ signature: await wallet.signMessage(data) });
  // });
  // socket.on('sign_transaction', async (data, callback) => {
  //   console.log('sign_transaction from extension wallet client', data);
  //   let tx: ethers.Transaction | VersionedTransaction | SolanaTransaction;
  //   if (data.network == 'solana') {
  //     try {
  //       tx = VersionedTransaction.deserialize(Buffer.from(data.transaction, 'base64'));
  //     } catch (e) {
  //       tx = SolanaTransaction.from(Buffer.from(data.transaction, 'base64'));
  //     }
  //   } else {
  //     tx = Transaction.from(data.transaction);
  //   }
  //   const signedTx = await wallet.signTransaction({ network: data.network, transaction: tx });
  //   console.log('signedTx', signedTx);
  //   callback({ signedTransaction: signedTx });
  // });
}
