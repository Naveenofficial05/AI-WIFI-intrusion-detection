let chartCtx, chartReady=false;const labels=[],traffic=[];
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function fmt(n){n=Number(n||0);if(n<1024)return n.toFixed(0)+' B/s';if(n<1024*1024)return (n/1024).toFixed(1)+' KB/s';return (n/1024/1024).toFixed(2)+' MB/s'}
function card(label,value,sub=''){return `<div class="card"><div class="label">${label}</div><div class="value">${esc(value)}</div><div class="sub">${esc(sub)}</div></div>`}
function drawChart(){if(!chartCtx)return;const c=chartCtx.canvas,w=c.clientWidth*devicePixelRatio,h=300*devicePixelRatio;c.width=w;c.height=h;chartCtx.clearRect(0,0,w,h);chartCtx.strokeStyle='#243044';chartCtx.lineWidth=1;for(let i=1;i<5;i++){let y=h*i/5;chartCtx.beginPath();chartCtx.moveTo(0,y);chartCtx.lineTo(w,y);chartCtx.stroke()}if(traffic.length<2)return;const max=Math.max(...traffic,1);chartCtx.strokeStyle='#7dd3fc';chartCtx.lineWidth=3;chartCtx.beginPath();traffic.forEach((v,i)=>{const x=i*(w-30)/(traffic.length-1)+15;const y=h-20-(v/max)*(h-45);if(i===0)chartCtx.moveTo(x,y);else chartCtx.lineTo(x,y)});chartCtx.stroke();chartCtx.fillStyle='#7dd3fc';traffic.forEach((v,i)=>{const x=i*(w-30)/(traffic.length-1)+15;const y=h-20-(v/max)*(h-45);chartCtx.beginPath();chartCtx.arc(x,y,3,0,Math.PI*2);chartCtx.fill()})}
function initChart(){chartCtx=document.getElementById('trafficChart').getContext('2d');chartReady=true;window.addEventListener('resize',drawChart)}
async function refresh(){
  try{
    const r=await fetch('/api/status',{cache:'no-store'});
    if(!r.ok) throw new Error(`API returned HTTP ${r.status}`);
    const d=await r.json();
    if(!d || typeof d!=='object') throw new Error('Invalid API response');

    document.getElementById('liveBadge').textContent=d.running?'LIVE MONITORING':'STOPPED';
    const devices=Array.isArray(d.connected_devices)?d.connected_devices:[];
    const alerts=Array.isArray(d.alerts)?d.alerts:[];
    const ai=d.ai||{};
    const thresholds=d.thresholds||{};

    document.getElementById('cards').innerHTML=[
      card('Wi-Fi',d.interface_ip?'Connected':'Not available',d.interface||'Unknown'),
      card('Active Connections',d.active_connections||0,'Current host connections'),
      card('Local Devices',devices.length,'LAN devices discovered'),
      card('Authorized Devices',d.authorized_devices||0,'Configured list'),
      card('Unknown Devices',d.unknown_devices||0,'Not in authorized list'),
      card('Traffic',fmt(d.traffic_rate),'Current rate')
    ].join('');

    const level=ai.overall_security_level||'NORMAL';
    const cls=level.toLowerCase().replace(' ','-');
    const box=document.getElementById('securityBox');
    box.className='security '+cls;
    document.getElementById('securityLevel').textContent=level;
    document.getElementById('securityText').textContent=ai.total_detections?`${ai.total_detections} detection(s) require admin review.`:'No suspicious activity detected.';
    document.getElementById('aiStats').innerHTML=[
      ['Detections',ai.total_detections||0],
      ['Threshold',fmt(thresholds.traffic_threshold||0)],
      ['DoS Threshold',fmt(thresholds.dos_threshold||0)]
    ].map(x=>`<div class="stat"><b>${esc(x[1])}</b><small>${esc(x[0])}</small></div>`).join('');

    const t=new Date().toLocaleTimeString();
    labels.push(t);traffic.push(Number(d.traffic_rate||0));
    if(labels.length>20){labels.shift();traffic.shift()}
    if(!chartReady)initChart();
    drawChart();
    document.getElementById('lastUpdated').textContent='Updated '+t;

    document.getElementById('alerts').innerHTML=alerts.length?alerts.slice().reverse().map(a=>`<tr><td>${esc(new Date(a.timestamp).toLocaleTimeString())}</td><td>${esc(a.detection_type)}</td><td>${esc(a.ip_address||'—')}</td><td class="sev ${esc(a.severity)}">${esc(a.severity)}</td><td>${esc(a.reason)}</td></tr>`).join(''):'<tr><td colspan="5">No alerts yet.</td></tr>';

    document.getElementById('devices').innerHTML=devices.length?devices.map(x=>`<tr><td>${esc(x.ip_address||'—')}</td><td class="${x.authorized?'ok':'bad'}">${x.authorized?'AUTHORIZED':'UNKNOWN'}</td><td>${esc(x.device_name||'—')}</td><td>${esc(x.mac_address||'N/A')}</td></tr>`).join(''):'<tr><td colspan="4">No local LAN devices discovered.</td></tr>';

    document.getElementById('info').innerHTML=[
      ['Status',d.running?'RUNNING':'STOPPED'],
      ['Interface',d.interface||'N/A'],
      ['Local IP',d.interface_ip||'N/A'],
      ['Monitoring interval',(d.monitoring_interval??'N/A')+' sec'],
      ['Time window',(d.time_window_seconds??'N/A')+' sec'],
      ['Engine','AI rule/expert system'],
      ['Machine Learning','Not used'],
      ['Data source','Windows ARP/neighbour table + host connections']
    ].map(x=>`<div class="info-row"><span>${esc(x[0])}</span><b>${esc(x[1])}</b></div>`).join('');
  }catch(e){
    console.error('Dashboard status error:',e);
    document.getElementById('liveBadge').textContent='SERVER ERROR';
  }
}
refresh();setInterval(refresh,3000);
