import { bufferToBase64Url } from "../utils";

type AuthenticatorAttestationResponseWithOptionalMembers =
  AuthenticatorAttestationResponse & {
    getTransports?: () => "" | string[];
    getAuthenticatorData?: () => unknown;
    getPublicKey?: () => unknown;
    getPublicKeyAlgorithm?: () => unknown;
  };

type PublicKeyCredentialResponse = {
  response: {
    attestationObject: string;
    clientData: string;
    transports: string[] | undefined;
  };
  rawId: string;
  type: string;
};

export const Login = () => {
  /**
   * 1. RPサーバーからチャレンジを取得
   */
  const getChallengeFromRpServer = async () => {
    const response = await fetch("http://localhost:9000/rp/create");
    const challenge =
      (await response.json()) as PublicKeyCredentialCreationOptionsJSON;
    // (await response.json()) as PublicKeyCredentialCreationOptions;
    console.info(challenge);

    // const challengeOptions = response a;
    return challenge;
  };

  /**
   * 2. 取得したチャレンジ情報を元にブラウザのパスキー認証情報を取得
   */
  const createCredential = async (
    options: PublicKeyCredentialCreationOptionsJSON
    // options: PublicKeyCredentialCreationOptions
  ): Promise<PublicKeyCredential | null> => {
    // const parsedOptions = console.info(parsedOptions);

    try {
      const credential = await navigator.credentials.create({
        publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
      });
      if (!credential) {
        console.error("Credential の作成に失敗しました");
        return null;
      } else {
        console.info(credential);
        return credential as PublicKeyCredential;
      }
    } catch (error) {
      console.error(error);
      return null;
    }
  };

  /**
   * 3.
   */
  const fido2CompleteCreateCredential = async (
    credential: PublicKeyCredential
  ) => {
    // if (
    //   !(credential instanceof PublicKeyCredential) ||
    //   !(credential.response instanceof AuthenticatorAssertionResponse)
    // ) {
    //   // throw new Error(
    //   //   "credential.response is not an instance of AuthenticatorAssertionResponse"
    //   // );
    //   console.error(
    //     "credential.response is not an instance of AuthenticatorAssertionResponse"
    //   );
    //   return;
    // }
    console.info(typeof credential.response);

    console.info("===== credential =====");
    console.info(JSON.stringify(credential, null, 2));
    // const json = credential.response.clientDataJSON;
    // const attestationObjectB64 = credential.response.authenticatorData;
    const response = credential.response as AuthenticatorAttestationResponse;
    const [attestationObjectB64, clientDataJSON_B64] = await Promise.all([
      bufferToBase64Url(response.attestationObject),
      bufferToBase64Url(response.clientDataJSON),
    ]);

    const transports = (
      (
        response as unknown as AuthenticatorAttestationResponseWithOptionalMembers
      ).getTransports?.() || []
    ).filter((transport) =>
      ["ble", "hybrid", "internal", "nfc", "usb"].includes(transport)
    );

    return {
      response: {
        attestationObject: attestationObjectB64,
        clientData: clientDataJSON_B64,
        transports: transports.length ? transports : undefined,
      },
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
    } as PublicKeyCredentialResponse;
  };

  /**
   * 4. RPサーバーからチャレンジを取得
   */
  const registPublicKeyCredential = async (
    credentialResponse: PublicKeyCredentialResponse,
    jsonOptions: PublicKeyCredentialCreationOptionsJSON
  ) => {
    console.info(credentialResponse);
    const response = await fetch("http://localhost:9000/rp/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Challenge: jsonOptions.challenge,
      },
      body: JSON.stringify(credentialResponse),
    });

    // const challengeOptions = response a;
    return await response.json();
  };

  const startRegistFidoAuth = async () => {
    // 1. チャレンジ情報取得
    const jsonOptions = await getChallengeFromRpServer();
    // 2. 取得したチャレンジ情報を元にブラウザのパスキー認証情報を取得
    const credential = await createCredential(jsonOptions);
    if (!credential) {
      console.error("パスキー認証情報の取得に失敗しました");
      return;
    }
    // 3. 取得したパスキー認証情報を元に、チャレンジ情報の検証を行う
    const response = await fido2CompleteCreateCredential(credential);
    // responseをバックエンドの/rp/verifyにPOSTする
    const result = await registPublicKeyCredential(response, jsonOptions);
    console.info("認証結果", result);
  };

  return (
    <div>
      <button onClick={startRegistFidoAuth}>get Challenge</button>
    </div>
  );
};
