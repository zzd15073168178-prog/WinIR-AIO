"""
Unit tests for Parsers
"""
import pytest
from src.core.parsers import CSVParser, AutorunsParser, EventLogParser


class TestCSVParser:
    """Test CSVParser"""
    
    @pytest.mark.unit
    def test_parse_simple_csv(self, csv_parser, sample_csv_data):
        """Test parsing simple CSV data"""
        result = csv_parser.parse(sample_csv_data)
        assert len(result) == 2
        assert result[0]['Header1'] == 'Value1'
        assert result[1]['Header2'] == 'Value5'
    
    @pytest.mark.unit
    def test_parse_empty_data(self, csv_parser):
        """Test parsing empty data"""
        result = csv_parser.parse("")
        assert result == []
    
    @pytest.mark.unit
    def test_parse_with_bom(self, csv_parser):
        """Test parsing CSV with BOM"""
        data_with_bom = '\ufeffHeader1,Header2\nValue1,Value2'
        result = csv_parser.parse(data_with_bom)
        assert len(result) == 1
        assert 'Header1' in result[0]
    
    @pytest.mark.unit
    def test_parse_with_custom_delimiter(self, csv_parser):
        """Test parsing with custom delimiter"""
        data = "Header1;Header2\nValue1;Value2"
        result = csv_parser.parse(data, delimiter=';')
        assert len(result) == 1
        assert result[0]['Header1'] == 'Value1'
    
    @pytest.mark.unit
    def test_parse_with_skip_lines(self, csv_parser):
        """Test skipping initial lines"""
        data = "Skip this\nSkip this too\nHeader1,Header2\nValue1,Value2"
        result = csv_parser.parse(data, skip_lines=2)
        assert len(result) == 1
        assert result[0]['Header1'] == 'Value1'


class TestAutorunsParser:
    """Test AutorunsParser"""
    
    @pytest.mark.unit
    def test_parse_autoruns_data(self, sample_autoruns_data):
        """Test parsing Autoruns CSV output"""
        result = AutorunsParser.parse(sample_autoruns_data)
        assert len(result) == 1
        assert result[0]['entry'] == 'TestApp'
        assert result[0]['enabled'] == 'enabled'
    
    @pytest.mark.unit
    def test_parse_empty_entries(self):
        """Test filtering empty entries"""
        data = "Entry Location,Entry,Image Path\n,,\nHKLM,Test,C:\\test.exe"
        result = AutorunsParser.parse(data)
        # Should filter out the empty entry
        assert len(result) == 1
    
    @pytest.mark.unit
    def test_key_normalization(self):
        """Test that keys are normalized (lowercase, stripped)"""
        data = "Entry Location  ,  Entry  \nHKLM,TestApp"
        result = AutorunsParser.parse(data)
        assert 'entry location' in result[0]
        assert result[0]['entry location'] == 'HKLM'


class TestEventLogParser:
    """Test EventLogParser"""
    
    @pytest.mark.unit
    def test_parse_json(self):
        """Test parsing JSON event log data"""
        json_data = '''[
            {"Id": 4624, "Message": "Login success"},
            {"Id": 4625, "Message": "Login failure"}
        ]'''
        result = EventLogParser.parse_json(json_data)
        assert len(result) == 2
        assert result[0]['Id'] == 4624
    
    @pytest.mark.unit
    def test_parse_empty_json(self):
        """Test parsing empty JSON"""
        result = EventLogParser.parse_json("")
        assert result == []
    
    @pytest.mark.unit
    def test_parse_text_list(self):
        """Test parsing text list format"""
        data = """TimeCreated : 2025-11-23
Id : 4624
Message : Login

TimeCreated : 2025-11-23
Id : 4625
Message : Logout"""
        
        result = EventLogParser.parse_text_list(data)
        assert len(result) == 2
        assert result[0]['Id'] == '4624'
        assert result[1]['Message'] == 'Logout'

