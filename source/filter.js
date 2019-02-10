'use strict'

function filter (html) {
	const regexp = /<\/?\w+(\s*\w+=(\w+|"[^"]*")\s*)*>/g;//Регулярка, выбирающая тэги
	const ValueType = Object.freeze({ text: 1,
					  opening_tag: 2,
					  closing_tag: 3 });//Возможные типы нод в html
	let parsed = [];
	let cursor = 0;
	let tag = regexp.exec(html);
	while (tag !== null) {
		if (tag.index != cursor) {
			//Между предыдущей нодой и новым тэгом есть текст
			parsed.push({ type: ValueType.text,
				      value: html.substring(cursor, tag.index) });
		}
		if (tag[0].charAt(1) == '/') {
			//По регулярке нашли закрывающий тэг
			parsed.push({ type: ValueType.closing_tag,
				      value: tag[0],
				      name: tag[0].match(/<\/\w+/)[0].slice(2,-1)});
			for (let i=parsed.length-1; i>=0; i--) {
				if (parsed[i].type == ValueType.opening_tag &&
				    parsed[i].name == parsed[parsed.length-1].name &&
				    parsed[i].closed === null) {
					//Полагая, что тэги расположены в корректном порядке,
					//закрываем последний открытый тэг
					parsed[i].closed = parsed.length - 1;
					break;
				}
			}
		} else {
			//По регулярке нашли открывающий тэг
			parsed.push({ type: ValueType.opening_tag,
				      value: tag[0],
				      name: tag[0].match(/<\w+/)[0].slice(1,-1),
				      closed: null });
		}
		cursor = tag.index + tag[0].length;
		tag = regexp.exec(html);
	}
	if (cursor < html.length) {
		//Обрабатываем текст после последнего тэга
		parsed.push({ type: ValueType.text,
			      value: html.substring(cursor) });
	}

	let result = '';
	parsed.forEach(function(item) {
		if (item.type == ValueType.text) {
			result += esc(item.value);
		} else {
			if (item.type == ValueType.opening_tag && is_xss(item.value)) {
				//Экранируем пару XSS тэгов
				item.value = esc(item.value);
				if (item.closed !== null) {
					parsed[item.closed].value = esc(parsed[item.closed].value);
				}
			}
			result += item.value;
		}
	});
	return result;
};

function esc (str) {
	const htmlEscapes = {
        	'&': '&amp;',
        	'<': '&lt;',
        	'>': '&gt;',
        	'"': '&quot;',
        	"'": '&#39;'
    	};
   	return str.replace(/[&<>"']/g, function(match) {
		//Экранируем все символы в тексте
        	return htmlEscapes[match];
	});
};

function is_xss (tag) {
	let tag_name = tag.match(/<\w+/)[0].slice(1);
	const xss_tags = ['script'];
	if (xss_tags.includes(tag_name)) return true;
	let attrs = tag.match(/\w+=/g);
	if (attrs === null) return false;//В теге нет атрибутов
	attrs = attrs.map(function (elem) {
		return elem.slice(0,-1);
	});
	const xss_attrs = ['value', 'href', 'src', 'style', 'onblur', 'onchange', 'onclick', 'ondbclick', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown','onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onreset', 'onselect', 'onsubmit'];
	let has_xss_attr = false;
	attrs.forEach(function (item) {
		if (xss_attrs.includes(item)) has_xss_attr = true;
	});
	return has_xss_attr;
};
