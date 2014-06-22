Untitled
======================

安全なチャット作る用のリポジトリ．中身は無い．

メモ
======================

- 暗号化はブラウザ＆アプリ上で行う．サーバ上のデータだけでは解読困難．
- リアルで会ってアプリ使って鍵交換してsecureフラグを立てる(？)
- 誰が誰に送ったメッセージかデータ上は分からない
- 部屋Aにいるaと部屋Bにいるbが同一人物化どうかは両方の部屋にいる人間のみ知り得る
- 定期的にメッセージのキューのIDを推測できないものに変える
- 秘密鍵を預けておく機能．パスフレーズつけて妥協(？)


pub_sign: pub_key:"" users: [{users}]

account: {
 user_id: "1"
 mail: ""
 password: "option?" 
}

user:{
 id: "1"
 name: "hoge"
 public_keys: ["",...]

 encripted_privete: "option"
 object_encript_keys: [""]
 rooms: [ {id:"1", room_key:"1234567(crypted)" , secure:false }, {id:"2", room_key:"abcdef(crypted)" , secure:true }]
}

user_notify_slot: {
	slot_id: "(crypted_usr_id)"
	notify_list:[
		{data:"", sign:"", pubkey:""}
	]
}

room:{
  id: "12345"
  name: "crypted?"
  members:[{user_id:"(crypted)"},...]
}


room_msg_queue:{
 id:"" // id := sha1(salt + room_key + room_id + post_date)
 messages:[
  {data:"crypted_data"}
 ]
}


