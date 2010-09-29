package com.vodafone360.people.service.aidl;

import java.util.ArrayList;
import java.util.List;

import com.vodafone360.people.utils.LogUtils;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Binder;

public class SecurityManager {
    private static SecurityManager sInstance=null;

    /** We'll store the trusted signatures as a list */
    private final List<String> mTrustedSignatures;

    /** Need Context to check the application's UID */
    private final Context mContext;
    
    /** Need the package manager to inspect security information */
    private final PackageManager mPackageManager;

    /** This is a singleton class */
    private SecurityManager(Context applicationContext) {
        mTrustedSignatures = new ArrayList<String>(8);
        mContext = applicationContext;
        mPackageManager = mContext.getPackageManager();
        
        // Always trust the keys that signed the 360 People app
        try {
            for (Signature sig : 
                mPackageManager.getPackageInfo(mContext.getPackageName(),
                        PackageManager.GET_SIGNATURES).signatures) {
                mTrustedSignatures.add(sig.toCharsString());
            }
        } catch (NameNotFoundException e) {
            LogUtils.logE("Could not find PackageInfo for this our own " +
            		"application", e);
        }

        // James Elford's release key.
        mTrustedSignatures.add("308205763082035ea00302010202044ca305f0300d06092a864886f70d0101050500307d310b30090603550406130267623110300e06035504081307456e676c616e64310f300d060355040713064c6f6e646f6e31223020060355040a1319636f6d2e776f726470726573732e6a616d6573656c666f72643110300e060355040b1307556e6b6e6f776e311530130603550403130c4a616d657320456c666f7264301e170d3130303932393039323530345a170d3338303231343039323530345a307d310b30090603550406130267623110300e06035504081307456e676c616e64310f300d060355040713064c6f6e646f6e31223020060355040a1319636f6d2e776f726470726573732e6a616d6573656c666f72643110300e060355040b1307556e6b6e6f776e311530130603550403130c4a616d657320456c666f726430820222300d06092a864886f70d01010105000382020f003082020a0282020100974349c59dc5888cd18d9fd78954b14e05ea625a2ebc94b09cafcb19e226576020c9e4bcb964a728f612d3f0a554f0d14fd3ea7f6291e747a376a91c3eed18bdbf344151465af3ad45fa434271369ff7ef8f6953a2e60457d4d4912576b06a27c133309bf1343ac039dea3298546ab302ae021e5d5ecd668eba68bf1d2eca58fc5aba185ef620285c7610296b29901dd84831d861a0b72830302d0d4e1cd8655d431523733740fd3560f6d143ea28cfb5a14f0b73ca9dcd3cdc4f635cbd761ae92606c7642cc875412dbf0f7304f807c17dc5a3f2af40cd875efbb04b61354ed229eba54be57e4fee1a86329d71142f7054163aee431b533fe905e06391419ed348a1a0a41d8d42af5ee25b518e47b0a5f816eaadeb310995fe33d9a3026df863d838b8fd061e7908f056421e144b9f3e06d7dd13b56cfedcd6e8c7add90d4fb921f7f83ef11b70d551c273f66b8b78be5c92a29b525ef2c0feb3d97f450b495fb0d9db253cfcef038dc6f0d8d896eb03d499b8aefed46af12fd892b282d8d1d4153763396cbae8e929cc38815ff049746ea808ebc4236dda67eab28a27060508ca98aaf627b855535a021e05d65cb1ba88e1e5b446482819c104127d373d5a2513b43451ce5737179eb89ab99a8d485d92c8ab6cc8dbe7b7b89483f0dce4fd9a497f8d1d1623021c80877225935692d93809d755dfd472bdd98e7253cf976c90203010001300d06092a864886f70d01010505000382020100554a6a2978e70b92f0d670b3b9cc04b829c59f8cb8ec24a0b8ac950afd01b084121e433e3bed14010b3db939d88aa1f58fe08aedc4fc7e25d389c1755e951e30c2dd082bfad4164219e3abe68c92acf88568a3c75f0f6d222e0898123358dcf3cb0ea4a43274c40db0c6b39d5f8c16f0fd5e4be6a6b9c90b24928330735b46ed73d8ebd5c8a139c3d42681f2de84e78cb69d053275a1f74e33c3a39e674d513334c90a19106898a74342ab3068ad4c254f03e90c9562af514a1839d315e89ca96cf18e51d9579feac7dfd75b776aa3fd6d54c34a91812859a4bcf65721994e71c6b4404782506175fcf903d51c535412c0eae1465ccb17fa1c6d8bed457746779d71e4ca8da6dbbc670203dd3086bd4fcdde036f0cc63e7f191832aad6a8177b099dfbc6a61ea24d5d35499db6abb2cc6942ace6b14a7d5a79a2746c29eb9c88a24e74d4bfff556d0fb51743f4ea6655091656d9947e4d224a3e9dfc697528f52f358fa85f682a67f83fc4bfa5dc2ac440ad8415f98e4e45ecfad5f135f1133f35a827069184b0aaf82127be789fc455b3cefe07a2459f4f17e87bec4466c28b20effcc52afa42b1912d0dbb3603a24abe69a1499669773c3a28fbd8708f5439169286fe44dcbbb7d3861da00a6b3466eca158ccf3a8ee8feb0f14e063ca31d2ba0c57ec303271dee7c4b5edfabf493a5fa864c97c0e7adab22538c5b1bc45d2");

        // James Elford's debugging key.
        //mTrustedSignatures.add("308201e53082014ea00302010202044c3c9509300d06092a864886f70d01010505003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3130303731333136333230395a170d3131303731333136333230395a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730819f300d06092a864886f70d010101050003818d0030818902818100b16f2df90f01bf181130d6c7dc46ee456fb347b30533344794b3062875ebee6e757e9e916e716e9fc4e5a7e1904e266bf44d7abf6f04b85d5a45e7017dbaedec4813e6f03b9f9f9923e9be244d507d697d723baf55f7550a61647aeb42fce6a1c83da2ed0bccd21153440ac7fd82399b8d8e0b6dbd632eb97b3f8b10597505130203010001300d06092a864886f70d01010505000381810098c6941ed6cebde513f2896a90c7305d81a6336b76e52d80a77b5a389092bdeb9102cad1c3173e91cab542f612d3b88868b15c0695e2d630a467361b33d4c0b0038bd543dac22d20ab9c1545e6bbf0834f026a94f3ae0ec7a5c0e42da52b9396bc00ab3afeb7d4b36af891a21ec74750e7814bb55bafa3942ff610cb330e7ea8");

    }
    
    protected boolean checkAuthorised() {
        try {
            /*
             * Cycle through the incoming caller's signatures and authorize
             * the request if one of them is on the trustedSignatures list.
             */
            for (Signature sig : 
                mPackageManager.getPackageInfo(mPackageManager.getNameForUid(Binder.getCallingUid()),
                        PackageManager.GET_SIGNATURES).signatures) {
                if (mTrustedSignatures
                        .contains(sig.toCharsString())) {
                    return true;
                }
            }
            
        } catch (NameNotFoundException e) {
            LogUtils.logE("Couldn't find the package that called IPC call" +
                    " in 360 People IPC service", e);
        }

        /* This may crash the caller if their signature wasn't recognised */
        throw new SecurityException("Incoming caller is not signed by " +
                "a trusted public key.");

    }

    /** Only methods on this package need to know about the Security Manager */
    protected static SecurityManager 
    getInstance(Context applicationContext){
        if (sInstance == null) {
            sInstance = new SecurityManager(applicationContext);
        }

        return sInstance;
    }

}
