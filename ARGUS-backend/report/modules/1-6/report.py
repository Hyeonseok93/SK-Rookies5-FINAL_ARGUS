"""Generate ARGUS 1-6 PDF from newest W16 findings."""
import argparse,json,re
from collections import Counter
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import BaseDocTemplate,Frame,PageTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,Image,KeepTogether
NAVY=colors.HexColor('#10243E');BLUE=colors.HexColor('#1769AA');PALE=colors.HexColor('#EAF2F8');GRAY=colors.HexColor('#F4F6F7');RED=colors.HexColor('#B03A2E')
CASES=(
('JSON 본문 크기·형식 검증',('HttpMessageNotReadableException',),'상','1-6 p.55','DTO에 @Size/@Pattern/@Valid 적용;파싱 예외를 400으로 처리;역직렬화 타입 화이트리스트 적용'),
('Path 파라미터 타입 검증',('MethodArgumentTypeMismatchException',),'상','1-6 p.55','경로 정규식·범위 검증;타입 불일치는 400 처리;Injection 교차 확인'),
('비정상 경로 리소스 매핑',('NoResourceFoundException','NoStaticResource'),'중','6-1 p.109','404 고정 메시지 적용;경로·예외·스택 제거;API 오류 형식 통일'),
('필수 파라미터 누락',('MissingServletRequestParameterException',),'중','1-6 p.55','Bean Validation 적용;누락 예외는 400 처리;요청 크기·파트 수 제한'),
('HTTP 메서드·Content-Type',('HttpRequestMethodNotSupportedException','HttpMediaTypeNotSupportedException'),'하','7-1 p.124 / 6-1 p.109','필요한 메서드·타입만 허용;405·415 반환;공통 오류 처리 조정'),
('DB 컬럼 길이 초과',('InvalidDataAccessResourceUsageException',),'상 권고','1-6 p.55','DB 길이와 같은 @Size 적용;SQL·테이블·컬럼 제거;최우선 조치'))
DETAILS={
'JSON 본문 크기·형식 검증':('요청 본문 JSON이 기대 타입·구조와 다르면 Jackson 파서 예외가 error.systemMessage에 노출됩니다. 1KB~10KB 문자열, 50단계 중첩 객체·배열 등도 사전 제한 없이 파서까지 도달했습니다.','enum 역직렬화 실패 응답에 SUPER_ADMIN을 포함한 권한 계층이 노출되는지 수동 확인이 필요합니다.'),
'Path 파라미터 타입 검증':('Long 타입 경로 변수에 특수문자, 와일드카드, 불리언 또는 역할 문자열을 넣으면 타입 변환 예외가 500으로 반환됩니다. 정상 구현은 400 또는 404로 처리해야 합니다.','SQL 형태 payload가 여기서는 타입 변환에서 차단되지만 다른 진입점에서 DB 계층까지 도달하지 않는지 확인해야 합니다.'),
'비정상 경로 리소스 매핑':('경로 조작 payload로 존재하지 않는 정적·동적 경로가 구성되면 리소스 매핑 예외와 내부 처리 정보가 500 응답에 포함됩니다.','발생량이 많고 baseline 미검증 항목이 포함되어 대표 표본을 재현해 취약·노이즈 비율을 확정해야 합니다.'),
'필수 파라미터 누락':('멀티파트 폭탄이나 대형 중복 키 JSON 처리 중 title, name, email 같은 필수 값이 누락되면 예외가 500으로 노출됩니다.','입력 크기 문제와 단순 필수 값 누락을 분리해 재현하고 멀티파트 자원 고갈 여부도 별도 확인해야 합니다.'),
'HTTP 메서드·Content-Type':('지원하지 않는 HTTP 메서드나 Content-Type 요청이 표준 405·415 대신 500으로 반환되고 내부 예외 클래스가 노출됩니다.','자동 캡처가 없는 사례는 동일 요청을 재현하여 수정 전·후 상태코드를 증빙해야 합니다.'),
'DB 컬럼 길이 초과':('10KB 입력이 애플리케이션 검증을 통과해 DB INSERT까지 도달하고 실제 SQL, members 테이블 및 컬럼 구성이 응답에 노출됩니다.','발생 건수는 적지만 실제 DB 구조가 노출된 유일한 사례이므로 자동 등급보다 높게 재평가해야 합니다.'),
}
GUIDE={
'1-6 p.55':'''사용자로부터 전달된 입력(파라미터) 값을 신뢰하지 말고 서버단에서 사용자로부터 전달된 데이터의 크기와 데이터의 형을 확인해 사용해야하며, 직렬화 및 역직렬화(언마샬)를 통해 객체를 사용할 때에는 화이트리스트로 정의해 사용해야합니다.<br/><br/>- Buffer Overflow 버퍼오버플로우<br/>웹 애플리케이션에 전달되는 모든 입력 값을 허용된 크기만 받을 수 있도록 설정 해야하며, 오버플로우 위험성이 존재하는 함수(strcpy, gets 등)는 사용을 자제해야 합니다. 이에 대한 대응 방안으로는 아래와 같습니다.<br/><br/>- 웹 서버 및 WAS 서버 버전을 안정성이 검증된 최신 버전으로 유지<br/>- 웹 애플리케이션에 전달되는 파라미터 값을 허용된 크기만 받을 수 있도록 설정하고, 크기를 초과하여 오류가 발생한 경우에는 오류 페이지를 반환하지 않도록 설정<br/>- 동적 메모리 할당을 위해 크기를 사용하는 경우 음수 값 검증<br/><br/>- 포맷스트링<br/>포맷스트링을 함수의 입력 파라미터로 직접 사용하지 말고, 간접적으로 참조가 되도록 설정해야 합니다. 이에 대한 대응 방안으로는 아래와 같습니다.<br/><br/>- 컴파일러에서 문자열 입력 포맷에 대한 자체적인 검사를 내장하고 있으므로 문자열 입력 포맷 검증 후 소스 코드에 적용<br/>※ GCC 컴파일러는 문자열 입력 포맷과 실제 입력이 맞지 않는 경우 경고 옵션이 존재하나 해당 방식은 컴파일 과정에서만 검증가능하며, 런타임 상황에서는 FuzzTesting을 이용하여 포맷스트링 버그가 존재하는지 검증이 필요함<br/>- 웹 서버 프로그램 최신 보안패치 적용<br/>- 웹 사이트에서 사용자가 입력한 파라미터 값 처리 중에 발생한 경우 사용자 입력 값의 유효성에 대한 검증 로직을 구현<br/><br/>- 역직렬화(Deserialization)<br/>웹 애플리케이션에 불필요한 경우 역직렬화를 사용하지 않도록 설정하거나, 사용자로부터 전달된 입력 값에 대해 White List 방식 또는 Black List 방식의 검증 로직을 구현하여 인증된 객체만 역직렬화가 수행되도록 설정해야 합니다. 또한, 역직렬화 과정에서 객체의 변조 여부를 점검할 수 있도록 무결성 검증 로직을 추가하여 주시기 바랍니다.''',
'6-1 p.109':'''모든 에러(403 error, 404 error, 500 error, DB 에러, 애플리케이션 에러 등) 발생시 별도의 에러 페이지를 생성하고 해당 에러 페이지로 이동 가능하도록 구현해야 합니다.<br/><br/>또한 별도 WAS를 웹 서버(apache, iis 등)와 연동하여 사용하는 경우는 WAS에 에러페이지 처리와 함께 웹 서버에서 에러페이지 설정을 적용하여 시스템 구성 시의 디폴트 오류 페이지나 메시지의 어떤 정보도 노출되지 않도록 해야 합니다.<br/><br/>WEB/WAS에 대한 에러페이지 설정은 WEB/WAS 환경 구성 시에 디자인 요소가 없는 디폴트 설정을 하게 됩니다. 에러페이지에 대한 서비스 별 디자인을 입히고자 할 경우에는 Default 설정 위치에 같은 파일명으로 디자인된 에러페이지를 upload하면 됩니다. 디폴트 에러페이지 위치는 서버 환경 구성 문서를 통해 전달됩니다.<br/>※ 디폴트 에러페이지 위치가 서버 환경 구성 문서에 누락되었을 경우 서버관리자에게 문의하시면 됩니다.<br/><br/>WEB/WAS에서 설정이 필요한 HTTP Error Code<br/>400: 요청 실패. 문법상 오류로 서버가 요청사항을 이해하지 못함<br/>401: 클라이언트 인증 실패<br/>403: 액세스 금지. 접근이 거부된 파일을 요청함<br/>404: 찾을 수 없음. 서버가 요청한 파일이나 스크립트를 찾지 못함<br/>405: 메소드를 허용할 수 없음<br/>500: 서버 내부 오류<br/><br/>또한 민감한 정보를 포함하는 오류 메시지 및 시스템 내부 데이터나 디버깅 정보가 노출되지 않도록 함수 결과 값에 대한 적절한 처리와 예외상황(Exception) 발생시 정보가 화면에 출력되지 않도록 적절한 처리가 이루어져야 합니다.''',
'7-1 p.124 / 6-1 p.109':'''HTTP Method 중 일부는 웹 서버에 잠재적인 보안위협을 가져다 줄 수 있으므로 웹 서비스 운영에 필수적인 메소드(GET, POST, HEAD, OPTIONS) 이외 사용되지 않는 메소드(PUT, DELETE, TRACE 등)를 제거해야 합니다.<br/><br/>※ 서비스 및 운영상의 영향도를 확인하시어 설정하여 적용해야 합니다.<br/><br/>모든 에러(403 error, 404 error, 500 error, DB 에러, 애플리케이션 에러 등) 발생시 별도의 에러 페이지를 생성하고 해당 에러 페이지로 이동 가능하도록 구현해야 합니다.<br/><br/>또한 별도 WAS를 웹 서버(apache, iis 등)와 연동하여 사용하는 경우는 WAS에 에러페이지 처리와 함께 웹 서버에서 에러페이지 설정을 적용하여 시스템 구성 시의 디폴트 오류 페이지나 메시지의 어떤 정보도 노출되지 않도록 해야 합니다.<br/><br/>또한 민감한 정보를 포함하는 오류 메시지 및 시스템 내부 데이터나 디버깅 정보가 노출되지 않도록 함수 결과 값에 대한 적절한 처리와 예외상황(Exception) 발생시 정보가 화면에 출력되지 않도록 적절한 처리가 이루어져야 합니다.'''}
GUIDE['1-6 p.55 / 6-1 p.109']=GUIDE['1-6 p.55']+'<br/><br/>'+GUIDE['6-1 p.109']
def esc(v,n=800):
 s=str(v or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;');return s[:n]+('…' if len(s)>n else '')
def exception(r):
 v=str((r.get('response_analysis')or{}).get('exception_type')or'')
 if v:return v.rsplit('.',1)[-1]
 m=re.search(r'([A-Za-z]+Exception|NoStaticResource)',str(r.get('response_text_snippet')or''));return m.group(1)if m else''
def request_facts(r):
 req=r.get('request')or{};query=req.get('query')or{};body=req.get('json')or{}
 def clean(value):
  if not isinstance(value,dict):return value
  return {k:('***' if any(x in k.lower() for x in ('password','token','authorization')) else clean(v)) for k,v in value.items()}
 ids=[]
 for source,data in (('query',query),('body',body)):
  if isinstance(data,dict):ids += [f'{source}.{k}={v}' for k,v in data.items() if k.lower()=='id' or k.lower().endswith('id')]
 body_value=json.dumps(clean(body),ensure_ascii=False) if body else esc(req.get('body_text'),700)
 return [('Finding ID',r.get('id','-')),('사용 계정',r.get('role','-')),('주입 위치',r.get('attack_vector')or'요청 본문/멀티파트'),('ID·식별자 값',' · '.join(ids)or'해당 없음'),('실제 변조 요청',f"{r.get('method','')} {r.get('url','')}"),('Query',json.dumps(clean(query),ensure_ascii=False)if query else'-'),('Body',body_value or'-')]
def tab(data,widths,font,header=True):
 t=Table(data,colWidths=widths,repeatRows=1 if header else 0);cmd=[('FONTNAME',(0,0),(-1,-1),font),('FONTSIZE',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#D5DBDB')),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]
 if header:cmd += [('BACKGROUND',(0,0),(-1,0),NAVY),('TEXTCOLOR',(0,0),(-1,0),colors.white)]
 for row in range(2,len(data),2):cmd.append(('BACKGROUND',(0,row),(-1,row),GRAY))
 t.setStyle(TableStyle(cmd));return t

def decorate(canvas,doc):
 canvas.saveState();w,h=A4
 canvas.setFillColor(NAVY);canvas.rect(0,h-14*mm,w,14*mm,fill=1,stroke=0)
 canvas.setFillColor(colors.white);canvas.setFont(doc.bold_font,7);canvas.drawString(18*mm,h-9*mm,'ARGUS  ·  WEB/API SECURE-CODING DIAGNOSIS REPORT')
 canvas.setFillColor(colors.HexColor('#607D8B'));canvas.setFont(doc.regular_font,7);canvas.drawString(18*mm,9*mm,'CONFIDENTIAL · 내부 검토용');canvas.drawRightString(w-18*mm,9*mm,str(canvas.getPageNumber()))
 canvas.setStrokeColor(colors.HexColor('#D5DBDB'));canvas.line(18*mm,13*mm,w-18*mm,13*mm);canvas.restoreState()
def generate_report(report_dir:Path,output:Path|None=None)->Path:
 report_dir=Path(report_dir).resolve();runs=[p for p in(report_dir/'evidence'/'w16').glob('W16_*')if p.is_dir()and(p/'raw_findings.json').is_file()]
 if not runs:raise FileNotFoundError('W16 raw_findings.json이 없습니다')
 run=max(runs,key=lambda p:p.stat().st_mtime);rows=json.loads((run/'raw_findings.json').read_text(encoding='utf-8'));sm=json.loads((run/'summary.json').read_text(encoding='utf-8'));output=Path(output or report_dir/'ARGUS_결과서_1-6.pdf').resolve()
 a,b=Path('C:/Windows/Fonts/malgun.ttf'),Path('C:/Windows/Fonts/malgunbd.ttf')
 if a.is_file():pdfmetrics.registerFont(TTFont('KR',str(a)));pdfmetrics.registerFont(TTFont('KRB',str(b)));font,bold='KR','KRB'
 else:pdfmetrics.registerFont(UnicodeCIDFont('HYSMyeongJo-Medium'));font=bold='HYSMyeongJo-Medium'
 st={'t':ParagraphStyle('t',fontName=bold,fontSize=25,leading=32,textColor=NAVY),'h':ParagraphStyle('h',fontName=bold,fontSize=17,leading=23,textColor=NAVY,spaceBefore=5*mm,spaceAfter=3*mm),'c':ParagraphStyle('c',fontName=bold,fontSize=13,leading=18,textColor=NAVY,spaceBefore=3*mm),'b':ParagraphStyle('b',fontName=font,fontSize=9,leading=14,spaceAfter=2*mm),'x':ParagraphStyle('x',fontName=font,fontSize=7.5,leading=11)}
 st.update({'coverNo':ParagraphStyle('coverNo',fontName=bold,fontSize=30,leading=36,textColor=colors.white),'coverTitle':ParagraphStyle('coverTitle',fontName=bold,fontSize=19,leading=27,textColor=colors.white),'coverSub':ParagraphStyle('coverSub',fontName=font,fontSize=9,leading=15,textColor=colors.HexColor('#DDEAF4')),'badge':ParagraphStyle('badge',fontName=bold,fontSize=9,leading=12,textColor=colors.white,alignment=TA_CENTER)})
 st.update({'solutionTitle':ParagraphStyle('solutionTitle',fontName=bold,fontSize=18,leading=25,textColor=NAVY,spaceAfter=5*mm),'solution':ParagraphStyle('solution',fontName=font,fontSize=11,leading=18,textColor=colors.HexColor('#263238'),spaceAfter=3*mm),'solutionBasis':ParagraphStyle('solutionBasis',fontName=font,fontSize=10.5,leading=17,textColor=NAVY)})
 cover=Table([[Paragraph('WEB · API SECURE-CODING DIAGNOSIS REPORT',st['coverSub'])],[Paragraph('1-6',st['coverNo'])],[Paragraph('입력 값 크기 및 무결성 검증 오류',st['coverTitle'])],[Paragraph('Web/API 개발보안 Guideline v3.0.0 기준 · ARGUS W16 자동 진단',st['coverSub'])]],colWidths=[160*mm],style=TableStyle([('BACKGROUND',(0,0),(-1,-1),NAVY),('LEFTPADDING',(0,0),(-1,-1),14*mm),('RIGHTPADDING',(0,0),(-1,-1),14*mm),('TOPPADDING',(0,0),(-1,0),12*mm),('BOTTOMPADDING',(0,-1),(-1,-1),12*mm)]))
 S=[Spacer(1,18*mm),cover,Spacer(1,10*mm),tab([['진단 대상',sm.get('target','-')],['진단 일시',sm.get('scan_time','-')],['Run ID',sm.get('run_id',run.name)],['보고서 구분','CONFIDENTIAL · 내부 검토용']],[35*mm,125*mm],font,False),Spacer(1,12*mm),Paragraph('본 결과서는 자동 진단 결과와 증거 자료를 Web/API 개발보안 가이드 기준으로 정리한 문서입니다.',st['b']),PageBreak(),Paragraph('01 · EXECUTIVE SUMMARY',st['h']),Paragraph(f'1-6 진단 결과 {len(rows):,}건 전체를 예외·상태코드·판정 기준으로 동적 분류했습니다.',st['b'])]
 risk=sm.get('risk_breakdown')or{};status=(sm.get('counts')or{}).get('by_status')or{}
 S += [Paragraph('응답 심각도 분포',st['c']),tab([['CRITICAL','HIGH','MEDIUM','INFO'],[risk.get('CRITICAL',0),risk.get('HIGH',0),risk.get('MEDIUM',0),risk.get('INFO',0)]],[40*mm]*4,font),Paragraph('응답 상태코드 분포',st['c']),tab([['상태','건수','판정'],['500 Internal Server Error',status.get('500',0),'예외 유형별 동적 분류'],['400 Bad Request',status.get('400',0),'입력을 정상 거부'],['200 OK',status.get('200',0),'원 payload 재확인'],['TIMEOUT',status.get('TIMEOUT',0),'잠재적 DoS 별도 검토']],[55*mm,25*mm,80*mm],font)]
 grouped=[];summary=[['#','케이스','건수','위험도']];claimed=set()
 for c in CASES:
  rs=[r for r in rows if exception(r)in c[1]];grouped.append((c,rs));claimed.update(str(r.get('id'))for r in rs)
 remaining=[r for r in rows if str(r.get('id'))not in claimed];summary_only=[r for r in remaining if str(r.get('status_code'))=='400' and (r.get('triage_status')=='noise' or (r.get('classification')or{}).get('final_status')=='not_vulnerable')];remaining=[r for r in remaining if r not in summary_only];buckets={}
 for r in remaining:
  ex=exception(r);key=('exception',ex)if ex else('status',str(r.get('status_code')))
  buckets.setdefault(key,[]).append(r)
 for (kind,key),rs in sorted(buckets.items(),key=lambda item:(item[0][0],item[0][1])):
  if kind=='exception':name=f'미등록 예외 · {key}';risk='중';basis='1-6 p.55 / 6-1 p.109';solutions='입력값 검증 및 예외 처리 확인;내부 오류 정보 제거;수동 재현 후 전용 매핑 등록';exs=(key,);description=f'1-6 진단에서 기존 매핑에 없던 {key} 오류가 감지되었습니다.';review='미등록 예외이므로 요청·응답과 영향도를 수동 검토해야 합니다.'
  elif key=='400':name='정상 입력 거부 · HTTP 400';risk='정보';basis='1-6 p.55';solutions='현재 거부 동작 유지;오류 응답의 내부 정보 노출 여부 확인';exs=('예외 없음',);description='비정상 입력을 400으로 거부한 결과입니다.';review='정상 거부 여부와 민감정보 미노출을 표본 확인합니다.'
  elif key=='200':name='예상 외 성공 · HTTP 200';risk='중';basis='1-6 p.55';solutions='변조 입력 반영 여부 확인;정상 요청과 응답 비교;검증 로직 보강';exs=('예외 없음',);description='변조 입력 요청이 성공 응답을 반환했습니다.';review='실제 입력 반영 또는 우회 성공인지 반드시 재현해야 합니다.'
  elif key=='TIMEOUT':name='응답 지연·무응답 · TIMEOUT';risk='상';basis='1-6 p.55';solutions='입력 크기·중첩·파트 수 제한;요청 시간 및 자원 제한;DoS 재현 시험';exs=('예외 없음',);description='대형 또는 복잡 입력에서 요청이 제한 시간 내 완료되지 않았습니다.';review='자원 고갈 및 서비스 거부 가능성을 별도 성능 시험으로 확인해야 합니다.'
  else:name=f'미분류 응답 · {key}';risk='중';basis='1-6 p.55 / 6-1 p.109';solutions='요청·응답 수동 분석;입력 검증 및 오류 처리 점검';exs=('예외 없음',);description=f'분류 규칙에 없는 상태 {key} 결과입니다.';review='누락 방지를 위해 수동 검토 대상으로 출력했습니다.'
  DETAILS[name]=(description,review);grouped.append(((name,exs,risk,basis,solutions),rs))
 for i,(c,rs)in enumerate(grouped,1):summary.append([i,c[0],len(rs),c[2]])
 summary.append(['-', '정상 거부·노이즈 (요약)',len(summary_only),'정보'])
 if sum(len(rs) for _,rs in grouped)+len(summary_only)!=len(rows):raise RuntimeError('1-6 Finding coverage mismatch')
 S += [tab(summary,[10*mm,110*mm,20*mm,20*mm],font),PageBreak()]
 for i,(c,rs)in enumerate(grouped,1):
  name,exs,risk,basis,solutions=c;description,review=DETAILS[name];payloads=Counter(str(r.get('payload_name')or'-')for r in rs)
  casebar=Table([[Paragraph('위험도 '+risk,st['badge']),Paragraph('발생 '+str(len(rs))+'건',st['badge']),Paragraph('검토 필요',st['badge'])]],colWidths=[50*mm,50*mm,60*mm],style=TableStyle([('BACKGROUND',(0,0),(0,0),RED if risk.startswith('상') else BLUE),('BACKGROUND',(1,0),(-1,0),NAVY),('BOX',(0,0),(-1,-1),.5,NAVY),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
  S += [Paragraph('02 · 상세 진단 결과',st['h']),Paragraph(f'({i}) {name}',st['c']),casebar,Paragraph('예외 클래스: '+' / '.join(exs),st['b']),Paragraph(description,st['b']),Paragraph('사람 검토 필요 사유. '+review,st['b']),Paragraph('Payload 분포. '+' · '.join(f'{esc(k,80)}×{v}' for k,v in payloads.most_common()),st['b']),Paragraph('Findings · 대표 사례',st['c'])]
  for r in sorted(rs,key=lambda x:int(x.get('duplicate_count')or 0),reverse=True)[:2]:
   msg=(r.get('response_analysis')or{}).get('system_message')or r.get('response_text_snippet')or'-'
   facts=[['Payload 이름',Paragraph(esc(r.get('payload_name'),200),st['x'])]]+[[label,Paragraph(esc(value,900),st['x'])] for label,value in request_facts(r)]+[['서버 응답',Paragraph(esc(msg),st['x'])]]
   S.append(tab(facts,[28*mm,132*mm],font,False));S.append(Spacer(1,2*mm))
   image=run/'evidence_screenshots'/str(r.get('id'))/'evidence.png'
   if image.is_file():
    figure=Table([[Image(str(image),width=148*mm,height=83*mm,kind='proportional')],[Paragraph('증거 스크린샷 · '+esc(r.get('payload_name'),100),st['x'])]],colWidths=[152*mm],style=TableStyle([('BOX',(0,0),(-1,-1),.7,colors.HexColor('#B0BEC5')),('BACKGROUND',(0,1),(-1,1),GRAY),('LEFTPADDING',(0,0),(-1,-1),2*mm),('RIGHTPADDING',(0,0),(-1,-1),2*mm),('TOPPADDING',(0,0),(-1,-1),2*mm),('BOTTOMPADDING',(0,0),(-1,-1),2*mm)]));S += [figure,Spacer(1,3*mm)]
  urls=Counter(str(r.get('normalized_url')or r.get('url')or'-')for r in rs);ud=[['URL','건수']]+[[Paragraph(esc(u,500),st['x']),n]for u,n in urls.most_common()];box=Table([[Paragraph('가이드 대응방안 원문 · Web/API 개발보안 Guideline v3.0.0 '+basis+' — '+GUIDE[basis],st['solutionBasis'])]],colWidths=[160*mm],style=TableStyle([('BACKGROUND',(0,0),(-1,-1),PALE),('BOX',(0,0),(-1,-1),.9,BLUE),('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]));S += [Paragraph('관련 URL',st['c']),tab(ud if len(ud)>1 else ud+[['-',0]],[140*mm,20*mm],font),PageBreak(),Paragraph(f'({i}) {name} · 해결방안',st['solutionTitle']),box,Spacer(1,5*mm),Paragraph('ARGUS 적용 권고',st['c'])]+[Paragraph('• '+x,st['solution'])for x in solutions.split(';')]
  if i<len(grouped):S.append(PageBreak())
 S += [PageBreak(),Paragraph('03 · METHODOLOGY & GLOSSARY',st['h']),Paragraph('진단 방법론 및 용어 정의',st['c']),Paragraph('W16(argus-w16-embedded)은 KISA와 SK Shielders 입력 검증 페이로드를 API 트리 전체에 주입하고 HTTP 응답, 예외 클래스, 상태코드와 정보 노출을 기준으로 트리아지합니다.',st['b']),Paragraph('위험도 정의',st['c']),Paragraph('상: 내부 구조 노출 또는 높은 영향 가능성으로 즉시 조치. 중: 조건부 영향으로 재현 필요. 하: 제한적 영향 또는 표준 오류 처리 개선 항목.',st['b']),Paragraph('한계 및 주의사항',st['c']),Paragraph('본 결과는 단일 자동 run이며 baseline 미검증과 동적 응답에 따른 오탐 가능성이 있습니다. 상·중 항목은 동일 계정과 요청으로 재현하고 수정 후 상태코드와 오류 본문을 다시 확인해야 합니다.',st['b'])];doc=BaseDocTemplate(str(output),pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=20*mm,bottomMargin=17*mm,title='ARGUS 결과서 1-6');doc.regular_font=font;doc.bold_font=bold;doc.addPageTemplates(PageTemplate(id='argus',frames=[Frame(doc.leftMargin,doc.bottomMargin,doc.width,doc.height,id='main')],onPage=decorate));doc.build(S);return output
def main():
 backend=Path(__file__).resolve().parents[3];p=argparse.ArgumentParser();p.add_argument('--report-dir',type=Path,default=backend/'data'/'report'/'1-6');p.add_argument('--output',type=Path);a=p.parse_args();print(generate_report(a.report_dir,a.output))
if __name__=='__main__':main()


















