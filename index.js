// index.js

const kv = await Deno.openKv();
const QUEUE_KEY = ["comments"];
const MAX_QUEUE_SIZE = 10;

// 超长密码
const PASSWORD =
  "dF_O5#Oe:=^rxjxos.l#$E_+nNNynY&,R@nqRLWp@:Lu_O1uLPlqP(bg?=PT1A|oiMvE9&k#WAjXU>(^GKCq)jPN7,p*J*TQ:gOXvEzMN6d9e5Ni[XY,.Xc9WI!T9<12fv-Voye_B8/Q)v7y}pf^W.4%Nr&fjTL#c=jsJ|Xyq.f,5%ZezKevgx+Ld0-O]^Li<M?[7UZmEHyHIU<)&R9ewul-_f>bFtXt=cZ<sRgiTAR>jpMLBSX[Q]:)yU[[Hl6V";
export default {
  async fetch(req) {
    const url=new URL(req.url);
    const date=req.json();

    if(url.pathname==="/register"){
      const name=date.name;
      const key=date.key;
      const password=date.password;
      var digit=0,letter=0;
      if(name.length<3||name.length>20){
        return new Response("用户名需要3-20位", { status: 400 });
      }
      var f=0;
      for(var i of name){
        if(!((i>='0'&&i<='9'))||!((i>='a'&&i<='z'))||!(i>='A'&&i<='Z')||!(i=='_')){
          f=1;break;
        }
      }
      if(f){
        return new Response("用户名只能包含字母、数字、下划线，否则可能发生错误", { status: 400 });
      }
      for(var i of password){
        if(i>='0'&&i<='9') digit++;
        if((i>='a'&&i<='z')||(i>='A'&&i<='Z')) letter++;
      }
      if(password.length<8||!digit||!letter){
        return new Response("密码需要8位以上，且包含数字和字母", { status: 400 });
      }
      const keyValidityTime = await kv.get(["invitekey",key]);
      if(!keyValidityTime.value){
        return new Response("邀请码无效", { status: 400 });
      }
      if(keyValidityTime.value<Date.now()){
        return new Response("邀请码已过期", { status: 400 });
      }
      const user = await kv.get(["user",name]);
      if(user.value){
        return new Response("用户名已存在", { status: 400 });
      }
      await kv.set(["user",name],{password:password});
      await kv.delete(["invitekey",key]);
      return new Response("注册成功", { status: 200 });
    }
  },
};
