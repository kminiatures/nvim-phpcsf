local M = {};
local root = vim.loop.cwd()
local phpcs_path = "$HOME/.config/composer/vendor/bin/phpcs"
local phpcbf_path = "$HOME/.config/composer/vendor/bin/phpcbf"
local phpcs_standard = "PSR2"

local Job = require'plenary.job'
local lutils = require('phpcs.utils')

-- Config Variables
M.phpcs_path = vim.g.nvim_phpcs_config_phpcs_path or phpcs_path
M.phpcbf_path = vim.g.nvim_phpcs_config_phpcbf_path or phpcbf_path
M.phpcs_standard = vim.g.nvim_phpcs_config_phpcs_standard or phpcs_standard
M.last_stderr = ''
M.last_stdout = ''
M.nvim_namespace = nil

M.detect_local_paths = function ()
  if (lutils.file_exists('phpcs.xml')) then
    M.phpcs_standard = root .. '/phpcs.xml'
  end

  if (lutils.file_exists('vendor/bin/phpcs')) then
    M.phpcs_path = root .. '/vendor/bin/phpcs'
  end

  if (lutils.file_exists('vendor/bin/phpcbf')) then
    M.phpcbf_path = root .. '/vendor/bin/phpcbf'
  end

  M.nvim_namespace = vim.api.nvim_create_namespace("phpcs")
end

M.cs = function ()
  local bufnr = vim.api.nvim_get_current_buf()


  local buf_file = os.tmpname()..".php";
  local buf_content = vim.api.nvim_buf_get_lines(bufnr, 0, -1, true);
  local file = io.open(buf_file, "w")
  for _, line in ipairs(buf_content) do
    file:write(line .. "\n")
  end
  file:close()

  local report_file = os.tmpname();

  local opts = {
    command = M.phpcs_path,
    args = {
      "--report=json",
      "--report-file=" .. report_file,
      "--standard=" .. M.phpcs_standard,
      buf_file
    },
    writer = vim.api.nvim_buf_get_lines(bufnr, 0, -1, true),
    on_exit = vim.schedule_wrap(function()
      local file = io.open(report_file, "r")
      if file ~= nil then
        local content = file:read("*a")
        M.publish_diagnostic(content, bufnr, buf_file)
      end
      os.remove(report_file)
      os.remove(buf_file)
    end),
  }

  Job:new(opts):start()
end

--[[
--  new_opts = {
        bufnr = 0, -- Buffer no. defaults to current
        force = false, -- Ignore file size
        timeout = 1000, -- Timeout in ms for the job. Default 1000ms
    }
]]

M.cbf = function (new_opts)
  new_opts = new_opts or {}
  new_opts.bufnr = new_opts.bufnr or vim.api.nvim_get_current_buf()

  if not new_opts.force then
    if vim.api.nvim_buf_line_count(new_opts.bufnr) > 1000 then
      print("File too large. Ignoring code beautifier" )
      return
    end
  end

  local opts = {
    command = M.phpcbf_path,
    args = {
      "--standard=" .. M.phpcs_standard,
      vim.api.nvim_buf_get_name(new_opts.bufnr)
    },
    on_exit = vim.schedule_wrap(function(j)
      if j.code ~= 0 then
        vim.cmd("e")
      end
    end),
    cwd = vim.fn.getcwd(),
  }

  Job:new(opts):start()
end

M.publish_diagnostic = function (results, bufnr, buf_file)
	bufnr = bufnr or vim.api.nvim_get_current_buf()

    local diagnostics = parse_json(results, bufnr, buf_file)

    vim.diagnostic.set(M.nvim_namespace, bufnr, diagnostics)
end

function parse_json(encoded, bufnr, buf_file)
    local decoded = vim.json.decode(encoded)
    local diagnostics = {}
    local uri = buf_file

    local error_codes = {
        ['error'] = vim.lsp.protocol.DiagnosticSeverity.Error,
        warning = vim.lsp.protocol.DiagnosticSeverity.Warning,
    }

    if not decoded.files[uri] then
        return diagnostics
    end

    for _, message in ipairs(decoded.files[uri].messages) do
        table.insert(diagnostics, {
            severity = error_codes[string.lower(message.type)],
            lnum	 = tonumber(message.line) -1,
            col	 = tonumber(message.column) -1,
            message = message.message
        })
    end

    return diagnostics
end


M.detect_local_paths()

--- Setup and configure nvim-phpcsf
---
--- @param opts table|nil
---     - phpcs (string|nil):
---         PHPCS path
---     - phpcbf (string|nil):
---         PHPCBF path
---     - standard (string|nil):
---         PHPCS standard
M.setup = function (opts)
    if opts == nil then
        M.detect_local_paths()
        return
    end

    if opts.phpcs ~= nil then
        M.phpcs_path = opts.phpcs
    end

    if opts.phpcbf ~= nil then
        M.phpcbf_path = opts.phpcbf
    end

    if opts.standard ~= nil then
        M.phpcs_standard = opts.standard
    end
end

return M
